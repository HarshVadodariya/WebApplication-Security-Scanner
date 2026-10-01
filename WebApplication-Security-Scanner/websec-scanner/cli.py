"""Command-line runner.  Example:
    python cli.py https://staging.example.com --i-am-authorized --json report.json
"""
import argparse
import json
import sys

from scanner import ScanError, run_scan
from scanner.safety import TargetError


def main() -> int:
    ap = argparse.ArgumentParser(description="Passive web security misconfiguration scanner")
    ap.add_argument("url")
    ap.add_argument("--i-am-authorized", action="store_true", help="confirm you have permission to test the target")
    ap.add_argument("--max-pages", type=int, default=15)
    ap.add_argument("--delay", type=float, default=0.4, help="seconds between requests")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (staging only)")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    args = ap.parse_args()

    if not args.i_am_authorized:
        print("Refusing to scan: pass --i-am-authorized to confirm you have permission.", file=sys.stderr)
        return 2
    try:
        report = run_scan(args.url, args.max_pages, args.delay, verify_tls=not args.insecure)
    except (TargetError, ScanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    c = report["counts"]
    print(f"Target: {report['target']}  ({report['pages_scanned']} pages, {report['requests_made']} requests)")
    print("  ".join(f"{k}: {v}" for k, v in c.items()), "\n")
    for group in report["by_owasp"]:
        print(f"== {group['label_2021']}  [{group['label_2025']}]")
        for f in group["findings"]:
            print(f"  [{f['severity']:<6}] {f['title']}  ({f['cwe']})")
            print(f"           evidence: {f['evidence']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nJSON report written to {args.json}")
    return 0 if c["High"] == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
