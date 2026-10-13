#!/usr/bin/env python3
"""CLI: Phase 4.5 black-box SSRF test for an authorized target.

Sends a unique, disposable webhook.site callback URL as each listed
parameter's value, then polls for whether the target's server actually
made an outbound request to it — out-of-band confirmation, not a guess
from response timing. See src/security_toolkit/recon/ssrf_testing.py's
docstring for why webhook.site over interactsh.

Usage:
    python scripts/run_ssrf_test.py --target example-staging --points config/injection_points/example-staging.json
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.recon.injection_testing import load_injection_points
from security_toolkit.recon.ssrf_testing import CallbackServiceError, check_ssrf
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument(
        "--points", required=True,
        help="Path to a JSON file of points — use ones where the server fetches a URL on your behalf "
        "(webhooks, image proxy, PDF export, link previews)",
    )
    parser.add_argument("--max-wait", type=float, default=20.0, help="Seconds to wait for a callback per point")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    points = load_injection_points(args.points)
    if not points:
        print(f"ERROR: no points found in {args.points}", file=sys.stderr)
        return 1

    findings = []
    for point in points:
        try:
            result = check_ssrf(target, point, max_wait=args.max_wait)
        except CallbackServiceError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        findings.append(Finding(name=f"{point.name} — SSRF", flagged=result.flagged, detail=result.detail))

    report = build_report(title="SSRF Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    if report.has_flags:
        print("\n⚠ One or more points confirmed an outbound callback — SSRF confirmed, see the report.")
        return 2
    print("\nNo SSRF confirmed by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
