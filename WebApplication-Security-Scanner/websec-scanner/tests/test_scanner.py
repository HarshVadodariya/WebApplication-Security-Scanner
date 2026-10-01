"""Run with:  python -m unittest discover -s tests -v

Spins up a deliberately misconfigured local server and scans it.
"""
import functools
import os
import sys
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import run_scan  # noqa: E402
from scanner.safety import TargetError, validate_target  # noqa: E402

HITS: list[str] = []
INDEX = (b'<html><head><title>Demo</title></head><body>'
         b'<a href="/files/a.txt">file</a> <a href="/logout">logout</a></body></html>')


class Vulnerable(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS.append(self.path)
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(INDEX)))
            self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
            self.send_header("Set-Cookie", "prefs=dark; Path=/; Secure; HttpOnly; SameSite=Lax")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            self.wfile.write(INDEX)
        else:
            super().do_GET()


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["ALLOW_PRIVATE_TARGETS"] = "1"
        cls.tmp = tempfile.mkdtemp()
        os.mkdir(os.path.join(cls.tmp, "files"))
        for name in ("a.txt", "secret.bak"):
            with open(os.path.join(cls.tmp, "files", name), "w") as fh:
                fh.write("x")
        handler = functools.partial(Vulnerable, directory=cls.tmp)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.report = run_scan(f"http://127.0.0.1:{cls.port}/", max_pages=5, delay=0)
        cls.ids = {f["id"] for g in cls.report["by_owasp"] for f in g["findings"]}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_missing_headers(self):
        for fid in ("HDR-CSP-MISSING", "HDR-CLICKJACKING", "HDR-XCTO", "HDR-REFERRER", "HDR-TECH-DISCLOSURE"):
            self.assertIn(fid, self.ids)

    def test_cookie_flags(self):
        for fid in ("COOKIE-NO-SECURE:sessionid", "COOKIE-NO-HTTPONLY:sessionid", "COOKIE-NO-SAMESITE:sessionid"):
            self.assertIn(fid, self.ids)
        self.assertFalse(any(i.endswith(":prefs") for i in self.ids))  # well-configured cookie is clean

    def test_directory_listing_and_sensitive_file(self):
        listing = [f for g in self.report["by_owasp"] for f in g["findings"] if f["id"] == "DIR-LISTING"]
        self.assertTrue(listing)
        self.assertEqual(listing[0]["severity"], "High")  # secret.bak is listed
        self.assertTrue(any("/files/" in u for u in listing[0]["urls"]))

    def test_cookie_values_not_leaked(self):
        self.assertNotIn("abc123", str(self.report))

    def test_risky_links_not_requested(self):
        self.assertNotIn("/logout", HITS)

    def test_ssrf_guard_blocks_loopback_by_default(self):
        os.environ.pop("ALLOW_PRIVATE_TARGETS")
        try:
            with self.assertRaises(TargetError):
                validate_target("http://127.0.0.1:9/")
        finally:
            os.environ["ALLOW_PRIVATE_TARGETS"] = "1"


if __name__ == "__main__":
    unittest.main()
