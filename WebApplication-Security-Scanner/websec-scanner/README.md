# Web Application Security Scanner

A passive scanner that finds common **security misconfigurations** in web apps you are authorized to test, and reports them mapped to the **OWASP Top 10**.

Stack: Python, Requests, BeautifulSoup, Flask.

## Run

```bash
pip install -r requirements.txt
python app.py                      # UI at http://127.0.0.1:5000
python cli.py https://staging.example.com --i-am-authorized --json report.json
python -m unittest discover -s tests -v
```

Scanning `localhost` / private IPs is blocked by default (SSRF guard). For your own lab hosts:
`ALLOW_PRIVATE_TARGETS=1 python app.py`

## What it detects

| Area | Checks |
|---|---|
| Headers | CSP missing / `unsafe-inline` / `unsafe-eval` / wildcard sources, clickjacking (X-Frame-Options or `frame-ancestors`), HSTS missing or short, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Server` version and `X-Powered-By` disclosure |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` without `Secure`. Session-like names get higher severity. Cookie **values are never stored** |
| Directory listing | Probes directories found while crawling plus ~17 common ones (`/uploads/`, `/wp-content/uploads/`, `/backup/` ...). Detects "Index of" / "Directory listing" pages with BeautifulSoup. Escalates to High if backup/config-looking files are listed |
| Transport | HTTP not redirected to HTTPS |

## Layout

```
app.py              Flask UI + JSON API
cli.py              command-line runner
scanner/
  engine.py         crawl -> run checks -> build report
  checks.py         headers / cookies / directory listing
  fetcher.py        bounded, GET-only HTTP client
  safety.py         SSRF guard
  owasp.py          OWASP mapping (edit to suit your policy)
templates/, static/ report UI (HTML, print-to-PDF friendly)
tests/              spins up a deliberately misconfigured server
```

## Safety design

- Consent required (checkbox / `--i-am-authorized` / `"authorized": true`).
- GET only; no logins, no form submission, no payloads.
- Same-host only; redirects re-validated; links like `logout`/`delete` are skipped.
- Request budget, body-size cap, delay between requests, identifying User-Agent.
- The scanner's own pages send CSP, nosniff etc., and Jinja auto-escapes target-supplied evidence.

## Limitations

- Header/cookie checks see what the server sends to an unauthenticated client; authenticated areas are not covered.
- No JavaScript rendering; link discovery is static HTML only.
- DNS is validated before each request, but a hostile DNS server could in theory rebind between check and connect.
- OWASP mapping is by weakness type, not an official CWE roll-up. Verify labels at owasp.org/Top10.
- Scans run synchronously inside the request; use a job queue (Celery/RQ) for larger deployments.

## Ideas to extend

CORS misconfiguration check, `robots.txt`/`security.txt`, TLS protocol/cert checks, async scan jobs with progress, PDF export (WeasyPrint), scan history in SQLite, diff between two scans.
