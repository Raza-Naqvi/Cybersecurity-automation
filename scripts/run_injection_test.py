#!/usr/bin/env python3
"""CLI: Phase 4.5 black-box injection test (SQLi/NoSQLi/XSS) for an
authorized target.

Pure HTTP(S) — sends known-safe-to-send payloads at each listed
parameter and flags error-signature matches or unescaped reflection.
These are signals for manual confirmation, not a final verdict — see
src/security_toolkit/recon/injection_testing.py's docstring.

Usage:
    python scripts/run_injection_test.py --target example-staging --points config/injection_points/example-staging.json
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.injection_testing import (
    check_injection_point_rate_limiting,
    load_injection_points,
    run_injection_suite,
)
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--points", required=True, help="Path to a JSON file of injection points")
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the automatic rate-limit check per point")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    points = load_injection_points(args.points)
    if not points:
        print(f"ERROR: no injection points found in {args.points}", file=sys.stderr)
        return 1

    findings = []
    for point in points:
        results = run_injection_suite(target, point)
        for result in results:
            findings.append(
                Finding(
                    name=f"{point.name} — {result.category}",
                    flagged=result.flagged,
                    detail=f"payload={result.payload!r}\n{result.detail}",
                )
            )
        if not args.skip_rate_limit:
            rate_result = check_injection_point_rate_limiting(target, point)
            findings.append(Finding(name=rate_result.label, flagged=rate_result.flagged, detail=rate_result.detail))

    report = build_report(title="Injection Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    if report.has_flags:
        print("\n⚠ One or more payloads were flagged — confirm manually before reporting as a finding.")
        return 2
    print("\nNo injection signals flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
