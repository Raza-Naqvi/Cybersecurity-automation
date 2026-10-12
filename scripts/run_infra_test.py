#!/usr/bin/env python3
"""CLI: Phase 4.8 black-box infra checks for an authorized target.

Wraps testssl.sh (TLS/cert misconfiguration) and nikto (general server
misconfiguration/outdated-software scanning) — both run over the network
against the target's base_url, no filesystem/DB/server access needed.
Neither tool ships with this repo; install them separately.

Usage:
    python scripts/run_infra_test.py --target example-staging
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import ScopeError, load_authorized_target
from security_toolkit.recon.infra_testing import run_nikto, run_testssl
from security_toolkit.reporting.report import Finding, build_report, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--skip-testssl", action="store_true")
    parser.add_argument("--skip-nikto", action="store_true")
    parser.add_argument("--testssl-bin", default="testssl.sh")
    parser.add_argument("--nikto-bin", default="nikto")
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

    if not args.skip_testssl:
        try:
            result = run_testssl(target, testssl_bin=args.testssl_bin)
            findings.append(Finding(name="testssl.sh (TLS/cert checks)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="testssl.sh (TLS/cert checks)", flagged=True, detail=f"check skipped: {exc}"))

    if not args.skip_nikto:
        try:
            result = run_nikto(target, nikto_bin=args.nikto_bin)
            findings.append(Finding(name="nikto (server misconfiguration)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="nikto (server misconfiguration)", flagged=True, detail=f"check skipped: {exc}"))

    if not findings:
        print("Nothing to run — both checks were skipped.", file=sys.stderr)
        return 1

    report = build_report(title="Infra Test", target=target.name, findings=findings)
    json_path, html_path = write_report(report)

    print(f"Report written:\n  {json_path}\n  {html_path}")
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
