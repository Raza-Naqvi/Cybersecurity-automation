#!/usr/bin/env python3
"""CLI: Phase 4.7 black-box business-logic test for an authorized target.

Pure HTTP(S). Each case has to be learned from using the app normally
first — this doesn't guess at checkout/coupon/webhook logic for you. See
config/business_logic_cases.example.json and
src/security_toolkit/recon/business_logic_testing.py's docstring.

Usage:
    python scripts/run_business_logic_test.py --target example-staging --cases config/business_logic_cases/example-staging.json
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.business_logic_testing import (
    check_coupon_reuse,
    check_forged_webhook,
    check_price_tampering,
    check_rate_limited_action,
    load_business_logic_cases,
)
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--cases", required=True, help="Path to a JSON file of business-logic cases")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    cases = load_business_logic_cases(args.cases)
    findings = []

    for case in cases.price_tamper:
        result = check_price_tampering(target, case)
        findings.append(Finding(name=f"{result.case_name} — price tamper", flagged=result.flagged, detail=result.detail))

    for case in cases.coupon_reuse:
        result = check_coupon_reuse(target, case)
        findings.append(Finding(name=f"{result.case_name} — coupon reuse", flagged=result.flagged, detail=result.detail))

    for case in cases.rate_limited_action:
        result = check_rate_limited_action(target, case)
        findings.append(Finding(name=f"{result.case_name} — rate limiting", flagged=result.flagged, detail=result.detail))

    for case in cases.webhook_forgery:
        result = check_forged_webhook(target, case)
        findings.append(Finding(name=f"{result.case_name} — forged webhook", flagged=result.flagged, detail=result.detail))

    if not findings:
        print(f"ERROR: no cases found in {args.cases}", file=sys.stderr)
        return 1

    report = build_report(title="Business Logic Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    if report.has_flags:
        print("\n⚠ One or more checks were flagged — review before reporting as a confirmed finding.")
        return 2
    print("\nNo business-logic issues flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
