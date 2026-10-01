"""Flask front-end for the scanner.  Run:  python app.py  ->  http://127.0.0.1:5000"""
from __future__ import annotations

import collections
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

from scanner import ScanError, run_scan
from scanner.safety import TargetError

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

REPORTS: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
MAX_REPORTS = 50


def _clamp(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _scan_and_store(url: str, pages: int, insecure: bool):
    report = run_scan(url, max_pages=pages, verify_tls=not insecure)
    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = report
    while len(REPORTS) > MAX_REPORTS:
        REPORTS.popitem(last=False)
    return rid, report


@app.after_request
def add_security_headers(resp):
    # The scanner dogfoods the headers it checks for.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return render_template("index.html", error=None, form={})


@app.post("/scan")
def scan():
    form = request.form
    if not form.get("authorized"):
        return render_template("index.html", form=form,
                               error="Please confirm you are authorized to test this target."), 400
    try:
        rid, _ = _scan_and_store(form.get("url", ""), _clamp(form.get("max_pages"), 1, 30, 15),
                                 bool(form.get("insecure")))
    except (TargetError, ScanError) as exc:
        return render_template("index.html", form=form, error=str(exc)), 400
    return redirect(url_for("report", rid=rid))


@app.get("/report/<rid>")
def report(rid):
    data = REPORTS.get(rid)
    if data is None:
        abort(404)
    return render_template("report.html", r=data, rid=rid)


@app.get("/report/<rid>/json")
def report_json(rid):
    data = REPORTS.get(rid)
    if data is None:
        abort(404)
    resp = jsonify(data)
    resp.headers["Content-Disposition"] = f"attachment; filename=security-report-{rid}.json"
    return resp


@app.post("/api/scan")
def api_scan():
    body = request.get_json(silent=True) or {}
    if body.get("authorized") is not True:
        return jsonify(error='Set "authorized": true to confirm you have permission to test this target.'), 400
    try:
        rid, data = _scan_and_store(str(body.get("url", "")), _clamp(body.get("max_pages"), 1, 30, 15),
                                    bool(body.get("insecure")))
    except (TargetError, ScanError) as exc:
        return jsonify(error=str(exc)), 400
    return jsonify({"id": rid, **data})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
