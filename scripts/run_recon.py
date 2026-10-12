#!/usr/bin/env python3
"""CLI: Phase 4.2 black-box recon report for an authorized target.

Pure HTTP(S) — no filesystem, DB, or server access needed. Safe to run
against any staging target with just its base_url set in scope.json.

Usage:
    python scripts/run_recon.py --target example-staging
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.recon import fingerprint
from security_toolkit.reporting.report import Finding, build_report, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not target.base_url:
        print(f"ERROR: target '{target.name}' has no base_url in scope.json", file=sys.stderr)
        return 1

    findings = []

    exposed = fingerprint.check_exposed_files(target)
    flagged_files = [item for item in exposed if item.flagged]
    findings.append(
        Finding(
            name="Exposed sensitive files",
            flagged=len(flagged_files) > 0,
            detail="\n".join(f"{item.path} :: {item.detail}" for item in flagged_files) or "none reachable",
        )
    )

    headers = fingerprint.fingerprint_headers(target)
    findings.append(
        Finding(
            name="Tech fingerprint (headers + cookies)",
            flagged=False,
            detail=(
                f"headers: {headers.tech_headers or 'none revealed'}\n"
                f"cookie hints: {', '.join(headers.cookie_hints) or 'none'}"
            ),
        )
    )
    findings.append(
        Finding(
            name="Missing recommended security headers",
            flagged=len(headers.missing_security_headers) > 0,
            detail=", ".join(headers.missing_security_headers) or "all present",
        )
    )

    xmlrpc = fingerprint.check_xmlrpc(target)
    findings.append(
        Finding(name="xmlrpc.php exposure", flagged=bool(xmlrpc.risky_methods_exposed), detail=xmlrpc.detail)
    )

    robots = fingerprint.check_robots_and_sitemap(target)
    findings.append(
        Finding(
            name="robots.txt / sitemap.xml",
            flagged=False,
            detail=(
                f"sitemap present: {robots['sitemap_present']}\n"
                f"disallowed paths worth investigating: {', '.join(robots['disallowed_paths']) or 'none listed'}"
            ),
        )
    )

    report = build_report(title="Recon", target=target.name, findings=findings)
    json_path, html_path = write_report(report)
    print(f"Report written:\n  {json_path}\n  {html_path}")
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
