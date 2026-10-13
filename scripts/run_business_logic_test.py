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
import json
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.recon.business_logic_testing import (
    CouponReuseCase,
    PriceTamperCase,
    RateLimitedActionCase,
    WebhookForgeryCase,
    check_coupon_reuse,
    check_forged_webhook,
    check_price_tampering,
    check_rate_limited_action,
)
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def _load_cases(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--cases", required=True, help="Path to a JSON file of business-logic cases")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    data = _load_cases(args.cases)
    findings = []

    for item in data.get("price_tamper_cases", []):
        case = PriceTamperCase(
            name=item["name"],
            path=item["path"],
            method=item.get("method", "post"),
            param_name=item.get("param_name", "price"),
            param_location=item.get("param_location", "json"),
            tampered_value=item.get("tampered_value", 0.01),
            extra_params=item.get("extra_params", {}),
        )
        result = check_price_tampering(target, case)
        findings.append(Finding(name=f"{result.case_name} — price tamper", flagged=result.flagged, detail=result.detail))

    for item in data.get("coupon_reuse_cases", []):
        case = CouponReuseCase(
            name=item["name"],
            path=item["path"],
            code=item["code"],
            method=item.get("method", "post"),
            param_name=item.get("param_name", "coupon_code"),
            param_location=item.get("param_location", "json"),
            extra_params=item.get("extra_params", {}),
            max_allowed_uses=item.get("max_allowed_uses", 1),
        )
        result = check_coupon_reuse(target, case)
        findings.append(Finding(name=f"{result.case_name} — coupon reuse", flagged=result.flagged, detail=result.detail))

    for item in data.get("rate_limited_action_cases", []):
        case = RateLimitedActionCase(
            name=item["name"],
            path=item["path"],
            method=item.get("method", "post"),
            payload=item.get("payload", {}),
            param_location=item.get("param_location", "json"),
        )
        result = check_rate_limited_action(target, case)
        findings.append(Finding(name=f"{result.case_name} — rate limiting", flagged=result.flagged, detail=result.detail))

    for item in data.get("webhook_forgery_cases", []):
        case = WebhookForgeryCase(
            name=item["name"],
            path=item["path"],
            payload=item["payload"],
            bogus_signature_header=item.get("bogus_signature_header"),
            bogus_signature_value=item.get("bogus_signature_value", "t=0,v1=deadbeef"),
        )
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
