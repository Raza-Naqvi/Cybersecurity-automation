#!/usr/bin/env python3
"""CLI: Phase 4.10 ("document every finding") — pulls every flagged
finding across every scan already run for a target, and writes one
consolidated Markdown draft, grouped by scan type, with blank Impact/Fix
fields for you to fill in.

This automates the aggregation, not the judgement call: read the whole
draft once, add your own impact/fix notes, and only then is it ready to
send to the dev team — nothing here sends it anywhere on its own.

Usage:
    python scripts/generate_findings_report.py --target cheerlytics
    python scripts/generate_findings_report.py --target cheerlytics --upload   # also puts a copy on Cloudinary
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.findings_report import collect_flagged_findings, render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--upload", action="store_true", help="Also upload the draft to Cloudinary as a .md file")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    findings = collect_flagged_findings(target.name)
    markdown = render_markdown(target.name, findings)

    if args.upload:
        from datetime import datetime, timezone

        from security_toolkit.reporting.cloud_report import upload_text_file

        try:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            url = upload_text_file(markdown, target.name, f"findings-draft_{stamp}.md")
            print(f"Draft uploaded: {url}\n", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: upload failed ({exc}) — printing the draft below instead.\n", file=sys.stderr)

    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
