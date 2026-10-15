#!/usr/bin/env python3
"""CLI: Phase 4.8 black-box infra checks for an authorized target.

Wraps testssl.sh (TLS/cert misconfiguration), nikto (general server
misconfiguration/outdated-software scanning), nuclei (broad
CVE-template-based scanning), and OWASP ZAP's baseline scan (general
active/passive scanning) — all run over the network against the
target's base_url, no filesystem/DB/server access needed. None ship
with this repo; install them separately (testssl.sh/nikto are required,
nuclei/zap are optional — see docs/pentest-tools-howto.md). ZAP runs
via Docker (the official zaproxy/zap-stable image).

Usage:
    python scripts/run_infra_test.py --target example-staging
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.infra_testing import run_nikto, run_nuclei, run_testssl, run_zap_baseline
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--skip-testssl", action="store_true")
    parser.add_argument("--skip-nikto", action="store_true")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip the nuclei check")
    parser.add_argument("--skip-zap", action="store_true", help="Skip the OWASP ZAP baseline scan")
    parser.add_argument("--testssl-bin", help="Override the resolved testssl.sh command (PATH/vendor/ auto-detected otherwise)")
    parser.add_argument("--nikto-bin", help="Override the resolved nikto command (PATH/vendor/ auto-detected otherwise)")
    parser.add_argument("--nuclei-bin", help="Override the resolved nuclei command (PATH auto-detected otherwise)")
    parser.add_argument("--zap-bin", help="Override the resolved docker command used to run ZAP (PATH auto-detected otherwise)")
    parser.add_argument("--testssl-timeout", type=float, help="Seconds before giving up on testssl.sh (default 180)")
    parser.add_argument("--nikto-timeout", type=float, help="Seconds before giving up on nikto (default 300)")
    parser.add_argument("--nuclei-timeout", type=float, help="Seconds before giving up on nuclei (default 300)")
    parser.add_argument("--zap-timeout", type=float, help="Seconds before giving up on the ZAP baseline scan (default 300)")
    parser.add_argument("--zap-spider-minutes", type=int, default=1, help="How long ZAP's spider crawls before the passive scan (default 1)")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    if not target.base_url:
        print(f"ERROR: target '{target.name}' has no base_url set", file=sys.stderr)
        return 1

    findings = []

    if not args.skip_testssl:
        try:
            testssl_cmd = (args.testssl_bin,) if args.testssl_bin else None
            kwargs = {"timeout": args.testssl_timeout} if args.testssl_timeout else {}
            result = run_testssl(target, testssl_cmd=testssl_cmd, **kwargs)
            findings.append(Finding(name="testssl.sh (TLS/cert checks)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="testssl.sh (TLS/cert checks)", flagged=True, detail=f"check skipped: {exc}"))

    if not args.skip_nikto:
        try:
            nikto_cmd = (args.nikto_bin,) if args.nikto_bin else None
            kwargs = {"timeout": args.nikto_timeout} if args.nikto_timeout else {}
            result = run_nikto(target, nikto_cmd=nikto_cmd, **kwargs)
            findings.append(Finding(name="nikto (server misconfiguration)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="nikto (server misconfiguration)", flagged=True, detail=f"check skipped: {exc}"))

    if not args.skip_nuclei:
        try:
            nuclei_cmd = (args.nuclei_bin,) if args.nuclei_bin else None
            kwargs = {"timeout": args.nuclei_timeout} if args.nuclei_timeout else {}
            result = run_nuclei(target, nuclei_cmd=nuclei_cmd, **kwargs)
            findings.append(Finding(name="nuclei (CVE-template scanning)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="nuclei (CVE-template scanning)", flagged=True, detail=f"check skipped: {exc}"))

    if not args.skip_zap:
        try:
            zap_cmd = (args.zap_bin,) if args.zap_bin else None
            kwargs = {"timeout": args.zap_timeout} if args.zap_timeout else {}
            result = run_zap_baseline(target, zap_cmd=zap_cmd, spider_minutes=args.zap_spider_minutes, **kwargs)
            findings.append(Finding(name="OWASP ZAP (baseline scan)", flagged=result.flagged, detail=result.detail))
        except RuntimeError as exc:
            findings.append(Finding(name="OWASP ZAP (baseline scan)", flagged=True, detail=f"check skipped: {exc}"))

    if not findings:
        print("Nothing to run — all checks were skipped.", file=sys.stderr)
        return 1

    report = build_report(title="Infra Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
