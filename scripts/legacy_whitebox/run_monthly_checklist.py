#!/usr/bin/env python3
"""LEGACY / WHITE-BOX ONLY — see src/security_toolkit/legacy_whitebox/__init__.py.
Needs wp_path (filesystem), local npm source, and DB credentials, which
the security team does not have under the black-box testing agreement.
Not part of the normal workflow.

CLI: Monthly recurring checklist report for an authorized target.

Usage:
    python scripts/legacy_whitebox/run_monthly_checklist.py --target example-staging --npm-project /path/to/app

Only reports what's outdated/missing — never applies updates itself.
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target, load_db_config
from security_toolkit.reporting.report import Finding, build_report, write_report
from security_toolkit.legacy_whitebox import monthly_checklist as checklist

_LEGACY_WARNING = (
    "⚠ LEGACY/WHITE-BOX SCRIPT — this needs server filesystem + DB + local "
    "source access the security team doesn't have under the black-box "
    "testing agreement. See src/security_toolkit/legacy_whitebox/__init__.py.\n"
)


def main() -> int:
    print(_LEGACY_WARNING, file=sys.stderr)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--npm-project", action="append", default=[], help="Path to a Node project to audit (repeatable)")
    parser.add_argument("--backup-dir", help="Path to check backup freshness against")
    parser.add_argument("--access-log", help="Path to a server access log to scan for spikes")
    parser.add_argument("--skip-db", action="store_true")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    findings = []

    if target.wp_path:
        updates = checklist.check_wp_updates(target.wp_path)
        if updates.raw_error:
            findings.append(Finding(name="WordPress update check", flagged=True, detail=updates.raw_error))
        else:
            outdated = updates.core_update_available or updates.outdated_plugins or updates.outdated_themes
            detail_lines = []
            if updates.core_update_available:
                detail_lines.append("core: update available")
            if updates.outdated_plugins:
                detail_lines.append("plugins: " + ", ".join(updates.outdated_plugins))
            if updates.outdated_themes:
                detail_lines.append("themes: " + ", ".join(updates.outdated_themes))
            findings.append(
                Finding(
                    name="WordPress core/plugin/theme updates",
                    flagged=bool(outdated),
                    detail="\n".join(detail_lines) or "everything up to date",
                )
            )

    for project_path in args.npm_project:
        summary = checklist.run_npm_audit(project_path)
        if summary.raw_error:
            findings.append(Finding(name=f"npm audit ({project_path})", flagged=True, detail=summary.raw_error))
        else:
            total = sum(summary.vulnerability_counts.values()) if summary.vulnerability_counts else 0
            findings.append(
                Finding(
                    name=f"npm audit ({project_path})",
                    flagged=total > 0,
                    detail=str(summary.vulnerability_counts) if total else "no known vulnerabilities",
                )
            )

    if not args.skip_db and target.wp_path:
        try:
            db_config = load_db_config()
            rogue = checklist.check_rogue_admins(db_config, target.known_admin_logins)
            findings.append(
                Finding(
                    name="Unrecognized administrator accounts",
                    flagged=len(rogue) > 0,
                    detail="\n".join(f"#{r.user_id} {r.user_login}" for r in rogue) or "none",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding(name="Unrecognized administrator accounts", flagged=True, detail=f"check skipped: {exc}"))

    if args.backup_dir:
        freshness = checklist.check_backup_freshness(args.backup_dir)
        findings.append(
            Finding(
                name="Backup freshness",
                flagged=freshness.is_stale,
                detail=f"newest={freshness.newest_file} age_days={freshness.age_days}",
            )
        )

    if args.access_log:
        top_ips = checklist.summarize_access_log_spikes(args.access_log)
        findings.append(
            Finding(
                name="Top request sources (review for scripted/abusive traffic)",
                flagged=False,
                detail="\n".join(f"{ip}: {count}" for ip, count in top_ips) or "no entries",
            )
        )

    findings.append(
        Finding(
            name="Manual action items (not automatable)",
            flagged=False,
            detail="\n".join(f"- {item}" for item in checklist.MANUAL_CHECKLIST_ITEMS),
        )
    )

    report = build_report(title="Monthly Checklist", target=target.name, findings=findings)
    json_path, html_path = write_report(report)
    print(f"Report written:\n  {json_path}\n  {html_path}")
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
