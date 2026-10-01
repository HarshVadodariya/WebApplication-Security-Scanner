from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse

import requests

from .safety import TargetError, validate_target

UA = "WebSecScanner/1.0 (authorized assessment; read-only GET requests)"
MAX_BODY = 512 * 1024


class Fetcher:
    """Polite, bounded, GET-only HTTP client.

    - re-validates every redirect hop against the safety rules
    - never follows a redirect off the original host
    - caps body size, request count, and request rate
    - keeps every hop in `log` so cookies set on redirects are analysed too
    """

    def __init__(self, timeout=8.0, delay=0.4, max_requests=80, verify=True):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"})
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.verify = verify
        self.requests_made = 0
        self.log: list[requests.Response] = []
        self.errors: list[str] = []
        self._last = 0.0

    def _throttle(self) -> None:
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url: str, max_redirects: int = 4):
        host = urlparse(url).hostname
        resp = None
        for _ in range(max_redirects + 1):
            try:
                validate_target(url)
            except TargetError as exc:
                self.errors.append(f"{url}: {exc}")
                return resp
            if self.requests_made >= self.max_requests:
                self.errors.append("Request budget reached; scan truncated.")
                return resp
            self._throttle()
            try:
                self.requests_made += 1
                resp = self.session.get(
                    url, allow_redirects=False, timeout=self.timeout,
                    verify=self.verify, stream=True,
                )
                body = bytearray()
                for chunk in resp.iter_content(8192):
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        break
                resp._content = bytes(body)
                resp.close()
            except requests.RequestException as exc:
                self.errors.append(f"{url}: {type(exc).__name__}")
                return None
            self.log.append(resp)
            location = resp.headers.get("Location")
            if resp.is_redirect and location:
                nxt = urljoin(url, location)
                if urlparse(nxt).hostname != host:
                    return resp
                url = nxt
                continue
            return resp
        return resp
