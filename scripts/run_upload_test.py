#!/usr/bin/env python3
"""CLI: Phase 4.6 black-box file-upload test for an authorized target.

Pure HTTP(S) — uploads a handful of crafted but harmless probe files
(each echoing a unique marker instead of doing anything with execution)
and reports whether they were accepted and, if a file URL is available,
whether they executed. See
src/security_toolkit/recon/upload_testing.py's docstring for the two
signals and how to wire up execution confirmation.

Usage:
    python scripts/run_upload_test.py --target example-staging --cases config/upload_cases/example-staging.json
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.upload_testing import check_upload_case_rate_limiting, load_upload_cases, run_upload_test_case
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--cases", required=True, help="Path to a JSON file of upload test cases")
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the automatic rate-limit check per case")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    cases = load_upload_cases(args.cases)
    if not cases:
        print(f"ERROR: no upload cases found in {args.cases}", file=sys.stderr)
        return 1

    findings = []
    for case in cases:
        results = run_upload_test_case(target, case)
        for result in results:
            findings.append(
                Finding(
                    name=f"{case.name} — {result.payload_name}",
                    flagged=result.flagged,
                    detail=f"filename={result.filename_sent!r}\n{result.detail}",
                )
            )
        if not args.skip_rate_limit:
            rate_result = check_upload_case_rate_limiting(target, case)
            findings.append(Finding(name=rate_result.label, flagged=rate_result.flagged, detail=rate_result.detail))

    report = build_report(title="Upload Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    if report.has_flags:
        print("\n⚠ One or more uploads were flagged — review before reporting as a confirmed finding.")
        return 2
    print("\nNo upload issues flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
