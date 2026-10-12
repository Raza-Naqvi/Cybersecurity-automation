#!/usr/bin/env python3
"""LEGACY / WHITE-BOX ONLY — see src/security_toolkit/legacy_whitebox/__init__.py.
Needs wp_path (filesystem) + DB credentials, which the security team does
not have under the black-box testing agreement. Not part of the normal
workflow.

CLI: Phase 1 incident-triage report for an authorized target.

Usage:
    python scripts/legacy_whitebox/run_incident_triage.py --target example-staging

Only acts on targets listed in config/scope.json. Detection only — see
docstring in src/security_toolkit/legacy_whitebox/incident_triage.py for
what this does and does not do.
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target, load_db_config
from security_toolkit.reporting.report import Finding, build_report, write_report
from security_toolkit.legacy_whitebox import incident_triage as triage

_LEGACY_WARNING = (
    "⚠ LEGACY/WHITE-BOX SCRIPT — this needs server filesystem + DB access "
    "the security team doesn't have under the black-box testing agreement. "
    "See src/security_toolkit/legacy_whitebox/__init__.py before using this.\n"
)


def main() -> int:
    print(_LEGACY_WARNING, file=sys.stderr)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--days", type=int, default=30, help="Lookback window for modified files")
    parser.add_argument("--skip-db", action="store_true", help="Skip the rogue-admin DB check")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not target.wp_path:
        print(f"ERROR: target '{target.name}' has no wp_path in scope.json", file=sys.stderr)
        return 1

    findings = []

    modified = triage.find_recently_modified_php(target.wp_path, days=args.days)
    findings.append(
        Finding(
            name=f"Files modified in last {args.days} days",
            flagged=len(modified) > 0,
            detail="\n".join(f"{m.path}" for m in modified) or "none",
        )
    )

    uploads_php = triage.find_php_in_uploads(target.wp_path)
    findings.append(
        Finding(
            name="PHP files inside wp-content/uploads",
            flagged=len(uploads_php) > 0,
            detail="\n".join(uploads_php) or "none found",
        )
    )

    if uploads_php:
        webshells = triage.scan_for_webshell_signatures(uploads_php)
        findings.append(
            Finding(
                name="Webshell signature matches",
                flagged=len(webshells) > 0,
                detail="\n".join(f"{w.path} :: {w.matched_pattern}" for w in webshells) or "none",
            )
        )

    try:
        passed, output = triage.run_core_checksum_verify(target.wp_path)
        findings.append(
            Finding(name="wp core verify-checksums", flagged=not passed, detail=output or "clean")
        )
    except RuntimeError as exc:
        findings.append(Finding(name="wp core verify-checksums", flagged=True, detail=str(exc)))

    if not args.skip_db:
        try:
            db_config = load_db_config()
            rogue = triage.find_rogue_admin_accounts(db_config, target.known_admin_logins)
            findings.append(
                Finding(
                    name="Unrecognized administrator accounts",
                    flagged=len(rogue) > 0,
                    detail="\n".join(
                        f"#{r.user_id} {r.user_login} (registered {r.user_registered})"
                        for r in rogue
                    )
                    or "none — all admins match known_admin_logins",
                )
            )
        except Exception as exc:  # noqa: BLE001 - surface any DB/config error as a finding
            findings.append(Finding(name="Unrecognized administrator accounts", flagged=True, detail=f"check skipped: {exc}"))

    report = build_report(title="Incident Triage", target=target.name, findings=findings)
    json_path, html_path = write_report(report)

    print(f"Report written:\n  {json_path}\n  {html_path}")
    if report.has_flags:
        print("\n⚠ One or more checks were flagged — review the report before declaring this resolved.")
        return 2
    print("\nNo issues flagged by automated checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
