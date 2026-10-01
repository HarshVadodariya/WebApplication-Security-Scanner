"""The three requested checks: security headers, cookies, directory listings."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .models import Finding

HSTS_MIN_AGE = 15552000  # 180 days


def _f(id, title, sev, owasp, cwe, desc, rec, evidence="") -> Finding:
    return Finding(id=id, title=title, severity=sev, owasp=owasp, cwe=cwe,
                   description=desc, recommendation=rec, evidence=evidence)


# --------------------------------------------------------------------------
# 1. Security headers
# --------------------------------------------------------------------------
def _parse_csp(raw: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in raw.split(";"):
        bits = part.strip().split()
        if bits:
            directives.setdefault(bits[0].lower(), bits[1:])
    return directives


def _csp_weaknesses(raw: str, csp: dict[str, list[str]]) -> list[Finding]:
    out = []
    src = csp.get("script-src") or csp.get("default-src")
    if src is None:
        out.append(_f("HDR-CSP-NO-SCRIPT-SRC", "CSP does not restrict scripts", "Low", "A05", "CWE-693",
                      "The policy has neither script-src nor default-src, so script sources are unrestricted.",
                      "Add default-src 'self' or an explicit script-src.", raw[:200]))
        return out
    lowered = [s.lower() for s in src]
    protected = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
                    for s in lowered)
    if "'unsafe-inline'" in lowered and not protected:
        out.append(_f("HDR-CSP-UNSAFE-INLINE", "CSP allows 'unsafe-inline' scripts", "Medium", "A05", "CWE-693",
                      "'unsafe-inline' lets injected inline scripts run, which defeats most of the CSP's XSS protection.",
                      "Move inline scripts to files or use nonces/hashes, then remove 'unsafe-inline'.", raw[:200]))
    if "'unsafe-eval'" in lowered:
        out.append(_f("HDR-CSP-UNSAFE-EVAL", "CSP allows 'unsafe-eval'", "Low", "A05", "CWE-693",
                      "'unsafe-eval' permits eval()-style code execution from strings.",
                      "Refactor code that relies on eval/new Function and drop 'unsafe-eval'.", raw[:200]))
    if any(s in ("*", "http:", "https:", "data:") for s in lowered):
        out.append(_f("HDR-CSP-WILDCARD", "CSP script source is overly broad", "Medium", "A05", "CWE-693",
                      "A wildcard or bare scheme in script-src allows scripts from almost anywhere.",
                      "List specific trusted origins (or use nonces) instead of '*', 'https:' or 'data:'.", raw[:200]))
    return out


def check_headers(resp) -> list[Finding]:
    h = {k.lower(): v for k, v in resp.headers.items()}
    https = resp.url.lower().startswith("https://")
    out: list[Finding] = []

    csp_raw = h.get("content-security-policy")
    csp = _parse_csp(csp_raw) if csp_raw else {}
    if not csp_raw:
        out.append(_f("HDR-CSP-MISSING", "Content-Security-Policy header missing", "Medium", "A05", "CWE-693",
                      "No CSP is set, so the browser applies no policy limiting where scripts and other resources load from. "
                      "CSP is a key second layer of defence against XSS.",
                      "Add a CSP, starting from default-src 'self' and tightening. Trial it with "
                      "Content-Security-Policy-Report-Only first.", "Header absent"))
    else:
        out += _csp_weaknesses(csp_raw, csp)

    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(_f("HDR-CLICKJACKING", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "Medium",
                      "A05", "CWE-1021",
                      "The page can be embedded in a frame on another site, enabling clickjacking.",
                      "Send Content-Security-Policy: frame-ancestors 'self' (or 'none'); X-Frame-Options: DENY/SAMEORIGIN "
                      "for legacy browsers.", "Neither header present"))

    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(_f("HDR-HSTS-MISSING", "Strict-Transport-Security header missing", "Medium", "A02", "CWE-319",
                          "Without HSTS, browsers may still attempt plain HTTP, allowing SSL-stripping attacks.",
                          "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere.",
                          "Header absent"))
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < HSTS_MIN_AGE:
                out.append(_f("HDR-HSTS-WEAK", "HSTS max-age is too short", "Low", "A02", "CWE-319",
                              "A short HSTS lifetime leaves a window for downgrade attacks.",
                              "Use max-age of at least 15552000 (180 days); 31536000 is the common target.",
                              f"Strict-Transport-Security: {hsts}"))

    xcto = h.get("x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        out.append(_f("HDR-XCTO", "X-Content-Type-Options: nosniff missing", "Low", "A05", "CWE-693",
                      "Browsers may MIME-sniff responses and treat data as executable content.",
                      "Send X-Content-Type-Options: nosniff.",
                      "Header absent" if xcto is None else f"X-Content-Type-Options: {xcto}"))

    if "referrer-policy" not in h:
        out.append(_f("HDR-REFERRER", "Referrer-Policy header missing", "Low", "A05", "CWE-693",
                      "Full URLs (possibly containing tokens or IDs) may leak to other sites via the Referer header.",
                      "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).", "Header absent"))

    if "permissions-policy" not in h:
        out.append(_f("HDR-PERMISSIONS", "Permissions-Policy header missing", "Info", "A05", "CWE-693",
                      "Powerful browser features (camera, geolocation, etc.) are not explicitly restricted.",
                      "Send a Permissions-Policy disabling features the site does not use.", "Header absent"))

    server = h.get("server", "")
    if re.search(r"[A-Za-z][\w\-]*/\d", server):
        out.append(_f("HDR-SERVER-VERSION", "Server header discloses software version", "Low", "A05", "CWE-200",
                      "Exact versions help attackers match the server to known vulnerabilities.",
                      "Configure the web server to send a generic or no Server header.", f"Server: {server}"))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if name in h:
            out.append(_f("HDR-TECH-DISCLOSURE", "Technology disclosed in response headers", "Low", "A05", "CWE-200",
                          "Framework/runtime headers reveal the stack and sometimes its version.",
                          "Remove X-Powered-By and similar headers (e.g. expose_php=Off, server_tokens off).",
                          f"{name}: {h[name]}"))
    return out


# --------------------------------------------------------------------------
# 2. Cookies
# --------------------------------------------------------------------------
SESSION_RE = re.compile(r"(sess|sid|auth|token|jwt|login)", re.I)


def _is_session_cookie(name: str) -> bool:
    n = name.lower()
    return bool(SESSION_RE.search(n)) and "csrf" not in n and "xsrf" not in n


def _set_cookie_headers(resp) -> list[str]:
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), attrs


def check_cookies(resp) -> list[Finding]:
    out: list[Finding] = []
    for raw in _set_cookie_headers(resp):
        name, attrs = parse_set_cookie(raw)
        if not name:
            continue
        sess = _is_session_cookie(name)
        kind = "session/auth cookie" if sess else "cookie"
        # Evidence never includes the cookie value.
        evidence = "; ".join([f"{name}=<redacted>"] + [k if not v else f"{k}={v}" for k, v in attrs.items()])
        samesite = attrs.get("samesite", "").lower()

        if "secure" not in attrs:
            out.append(_f(f"COOKIE-NO-SECURE:{name}", f"Cookie '{name}' missing Secure flag",
                          "Medium" if sess else "Low", "A05", "CWE-614",
                          f"This {kind} can be sent over unencrypted HTTP, where it can be intercepted.",
                          "Add the Secure attribute and serve the site over HTTPS only.", evidence))
        if "httponly" not in attrs:
            out.append(_f(f"COOKIE-NO-HTTPONLY:{name}", f"Cookie '{name}' missing HttpOnly flag",
                          "Medium" if sess else "Low", "A05", "CWE-1004",
                          f"JavaScript can read this {kind}, so an XSS bug could steal it.",
                          "Add HttpOnly unless client-side script genuinely needs the value.", evidence))
        if not samesite:
            out.append(_f(f"COOKIE-NO-SAMESITE:{name}", f"Cookie '{name}' missing SameSite attribute", "Low", "A01",
                          "CWE-1275",
                          f"Without SameSite the {kind} relies on browser defaults for cross-site request protection.",
                          "Set SameSite=Lax (or Strict) explicitly; use None only with Secure and a clear need.", evidence))
        elif samesite == "none" and "secure" not in attrs:
            out.append(_f(f"COOKIE-SAMESITE-NONE-INSECURE:{name}", f"Cookie '{name}' uses SameSite=None without Secure",
                          "Medium", "A01", "CWE-1275",
                          "SameSite=None without Secure is rejected by modern browsers and exposes the cookie cross-site.",
                          "Add Secure, or switch to SameSite=Lax/Strict.", evidence))
    return out


# --------------------------------------------------------------------------
# 3. Directory listing
# --------------------------------------------------------------------------
SENSITIVE_RE = re.compile(r"\.(sql|bak|old|zip|tar|gz|7z|env|log|conf|ini|pem|key|swp|dump)$", re.I)


def check_directory_listing(resp) -> Finding | None:
    if resp.status_code != 200 or "html" not in resp.headers.get("Content-Type", "").lower():
        return None
    soup = BeautifulSoup(resp.text, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    h1 = soup.h1.get_text(" ", strip=True) if soup.h1 else ""
    anchors = [a for a in soup.find_all("a") if a.get("href")]
    texts = [a.get_text(" ", strip=True) for a in anchors]

    is_listing = (
        re.match(r"(index of|directory listing)", title, re.I)
        or re.match(r"(index of|directory listing)", h1, re.I)
        or any(t.lower() in ("parent directory", "[to parent directory]") for t in texts)
    )
    if not is_listing:
        return None

    entries = [t for a, t in zip(anchors, texts)
               if t and not a["href"].startswith("?") and t.lower() not in ("parent directory", "[to parent directory]")]
    sensitive = [e for e in entries if SENSITIVE_RE.search(e)]
    sample = ", ".join(entries[:5]) + (" ..." if len(entries) > 5 else "")
    return _f("DIR-LISTING", "Directory listing enabled", "High" if sensitive else "Medium", "A01", "CWE-548",
              "The server returns an index of files for this directory, helping attackers find backups, "
              "configs, uploads and other content that was never meant to be linked.",
              "Disable auto-indexing (nginx: autoindex off; Apache: Options -Indexes; IIS: Directory Browsing off) "
              "and add an index file or return 403/404.",
              f"{len(entries)} entries listed, e.g. {sample}" +
              (f" | sensitive-looking: {', '.join(sensitive[:3])}" if sensitive else ""))


# --------------------------------------------------------------------------
# Transport (supports the cookie/HSTS findings)
# --------------------------------------------------------------------------
def check_transport(start_url: str, final_resp) -> Finding | None:
    if start_url.lower().startswith("http://") and final_resp.url.lower().startswith("http://"):
        return _f("TLS-NOT-ENFORCED", "Site served over HTTP without redirecting to HTTPS", "Medium", "A02", "CWE-319",
                  "Traffic, including cookies and credentials, is sent in clear text.",
                  "Serve the site over HTTPS and redirect all HTTP requests (301) to HTTPS.",
                  f"{start_url} -> {final_resp.url} ({final_resp.status_code})")
    return None
