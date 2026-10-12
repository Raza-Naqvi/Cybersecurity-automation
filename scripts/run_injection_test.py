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
import json
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.recon.injection_testing import InjectionPoint, run_injection_suite
from security_toolkit.reporting.report import Finding, build_report, write_report


def _load_points(path: str) -> list[InjectionPoint]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [
        InjectionPoint(
            name=item["name"],
            path=item["path"],
            method=item.get("method", "get"),
            param_name=item.get("param_name", "q"),
            param_location=item.get("param_location", "query"),
            extra_params=item.get("extra_params", {}),
        )
        for item in data.get("points", [])
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--points", required=True, help="Path to a JSON file of injection points")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    points = _load_points(args.points)
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

    report = build_report(title="Injection Test", target=target.name, findings=findings)
    json_path, html_path = write_report(report)

    print(f"Report written:\n  {json_path}\n  {html_path}")
    if report.has_flags:
        print("\n⚠ One or more payloads were flagged — confirm manually before reporting as a finding.")
        return 2
    print("\nNo injection signals flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
