from __future__ import annotations

import posixpath
import re
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from .checks import check_cookies, check_directory_listing, check_headers, check_transport
from .fetcher import Fetcher
from .models import FindingStore
from .owasp import OWASP_TOP10, SEVERITY_ORDER, SEVERITY_RANK
from .safety import validate_target

CRAWLABLE_EXT = {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}
# GET requests must never trigger state changes, so skip risky-looking links.
SKIP_RE = re.compile(r"(logout|log-out|signout|sign-out|delete|remove|unsubscribe|destroy)", re.I)
COMMON_DIRS = ["uploads/", "upload/", "images/", "img/", "assets/", "static/", "files/", "media/",
               "backup/", "backups/", "logs/", "tmp/", "css/", "js/",
               "wp-content/uploads/", "wp-content/plugins/", "wp-includes/"]
MAX_DIRS = 30

CHECKS_RUN = [
    "Security headers: CSP (incl. weak policies), clickjacking, HSTS, X-Content-Type-Options, "
    "Referrer-Policy, Permissions-Policy, version disclosure",
    "Cookies: Secure, HttpOnly, SameSite on every Set-Cookie seen",
    "Directory listing: discovered directories plus common paths",
    "Transport: HTTP to HTTPS enforcement",
]


class ScanError(Exception):
    pass


def extract_links(base_url: str, html: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()
    for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"), ("img", "src"), ("iframe", "src")):
        for el in soup.find_all(tag):
            value = el.get(attr)
            if value:
                url = urldefrag(urljoin(base_url, value.strip()))[0]
                if url.startswith(("http://", "https://")):
                    links.add(url)
    return links


def _crawlable(url: str) -> bool:
    p = urlparse(url)
    if SKIP_RE.search(p.path + "?" + p.query):
        return False
    return posixpath.splitext(p.path)[1].lower() in CRAWLABLE_EXT


def directory_candidates(host: str, urls: set[str]) -> list[str]:
    found: set[str] = set()
    for u in urls:
        p = urlparse(u)
        if p.hostname != host:
            continue
        parts = [x for x in p.path.split("/") if x]
        if not p.path.endswith("/"):
            parts = parts[:-1]
        for i in range(1, len(parts) + 1):
            found.add("/" + "/".join(parts[:i]) + "/")
    discovered = sorted(found, key=lambda d: (d.count("/"), d))
    common = ["/" + c for c in COMMON_DIRS if "/" + c not in found]
    return (discovered + common)[:MAX_DIRS]


def run_scan(start_url: str, max_pages: int = 15, delay: float = 0.4, verify_tls: bool = True) -> dict:
    started = datetime.now(timezone.utc)
    start_url = validate_target(start_url.strip())
    host = urlparse(start_url).hostname
    fx = Fetcher(delay=delay, max_requests=max_pages + MAX_DIRS + 20, verify=verify_tls)
    store = FindingStore()

    queue, visited, discovered, pages = deque([start_url]), set(), set(), []
    cookie_idx = 0
    base = None

    def harvest_cookies():
        nonlocal cookie_idx
        for hop in fx.log[cookie_idx:]:
            for f in check_cookies(hop):
                store.add(f, hop.url)
        cookie_idx = len(fx.log)

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        resp = fx.get(url)
        harvest_cookies()
        if resp is None:
            if not pages and not queue:
                raise ScanError(f"Could not fetch the target. {'; '.join(fx.errors[-2:])}")
            continue
        if base is None:
            base = f"{urlparse(resp.url).scheme}://{urlparse(resp.url).netloc}"
            transport = check_transport(start_url, resp)
            if transport:
                store.add(transport, resp.url)
        pages.append(resp.url)
        is_html = "html" in resp.headers.get("Content-Type", "").lower()
        if is_html or len(pages) == 1:
            for f in check_headers(resp):
                store.add(f, resp.url)
        if is_html:
            for link in extract_links(resp.url, resp.text):
                if urlparse(link).hostname != host:
                    continue
                discovered.add(link)
                if link not in visited and _crawlable(link):
                    queue.append(link)

    if base is None:
        raise ScanError(f"Could not fetch the target. {'; '.join(fx.errors[-2:])}")

    for d in directory_candidates(host, discovered | set(pages)):
        resp = fx.get(urljoin(base, d))
        harvest_cookies()
        if resp is not None:
            finding = check_directory_listing(resp)
            if finding:
                store.add(finding, resp.url)

    return _build_report(start_url, started, pages, fx, store)


def _build_report(target, started, pages, fx, store) -> dict:
    findings = sorted(store.all(), key=lambda f: (SEVERITY_RANK[f.severity], f.owasp, f.id))
    counts = {s: 0 for s in SEVERITY_ORDER}
    groups: dict[str, list] = {}
    for f in findings:
        counts[f.severity] += 1
        groups.setdefault(f.owasp, []).append(f.to_dict())
    return {
        "target": target,
        "started": started.strftime("%Y-%m-%d %H:%M UTC"),
        "finished": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "pages_scanned": len(pages),
        "pages": pages,
        "requests_made": fx.requests_made,
        "counts": counts,
        "total": len(findings),
        "by_owasp": [{"key": k, **OWASP_TOP10[k], "findings": v} for k, v in sorted(groups.items())],
        "checks_run": CHECKS_RUN,
        "errors": fx.errors,
    }
