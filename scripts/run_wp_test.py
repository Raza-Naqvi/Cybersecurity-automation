#!/usr/bin/env python3
"""CLI: Phase 4.2/4.4 black-box WordPress enumeration for an authorized
target — our own alternative to WPScan (see recon/wp_enum.py).

Pure HTTP(S), no external tool/API token needed. Only meaningful
against a target with `"type": "wordpress"` in scope.json; run against
anything else it just reports "not WordPress" and stops.

Usage:
    python scripts/run_wp_test.py --target example-wordpress-staging
"""

from __future__ import annotations

import sys
from argparse import ArgumentParser

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.wp_enum import DEFAULT_USER_MAX_ID, run_wp_enum
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument(
        "--user-max-id", type=int, default=DEFAULT_USER_MAX_ID,
        help=f"How many ?author=N IDs to probe if the REST API doesn't reveal usernames (default {DEFAULT_USER_MAX_ID})",
    )
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the user-enumeration rate-limit check")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    if not target.base_url:
        print(f"ERROR: target '{target.name}' has no base_url in scope.json", file=sys.stderr)
        return 1

    result = run_wp_enum(target, user_max_id=args.user_max_id, check_rate_limit=not args.skip_rate_limit)

    findings = [Finding(name="WordPress detection", flagged=False, detail=result.detail)]

    if result.is_wordpress:
        plugin_lines = "\n".join(f"{p.slug} :: version {p.version or 'unknown'} ({p.source})" for p in result.plugins)
        findings.append(
            Finding(name="Plugin enumeration", flagged=False, detail=plugin_lines or "none detected")
        )

        theme_lines = "\n".join(f"{t.slug} :: version {t.version or 'unknown'} ({t.source})" for t in result.themes)
        findings.append(Finding(name="Theme enumeration", flagged=False, detail=theme_lines or "none detected"))

        findings.append(
            Finding(
                name="Username enumeration",
                flagged=len(result.usernames) > 0,
                detail=(f"FLAGGED: {', '.join(result.usernames)}" if result.usernames else "no usernames exposed"),
            )
        )

        if result.rate_limit is not None:
            findings.append(
                Finding(name=result.rate_limit.label, flagged=result.rate_limit.flagged, detail=result.rate_limit.detail)
            )

    report = build_report(title="WordPress Enumeration", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
