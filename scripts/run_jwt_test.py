#!/usr/bin/env python3
"""CLI: Phase 4.3 black-box JWT tampering test for an authorized target.

Pure HTTP + stdlib crypto — same techniques jwt_tool uses (alg confusion,
weak-secret brute force) but no external binary. Needs a captured token
(copy it from a browser's dev tools / Burp / the Authorization header
after logging in manually) and a protected endpoint to resubmit it to.

The storage-hint check (cookie vs JSON body, localStorage risk) runs as
part of `run_auth_test.py` instead, since that script already performs
the login and has the raw response.

Usage:
    python scripts/run_jwt_test.py --target example-staging --token eyJ... \\
        --protected-path /account [--public-key-file jwks_public.pem]
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.recon.jwt_testing import (
    JwtDecodeError,
    check_alg_none_bypass,
    check_jwt_claims,
    check_rs256_to_hs256_confusion,
    check_weak_hs256_secret,
)
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--token", required=True, help="A captured JWT (e.g. from a browser's Authorization header)")
    parser.add_argument("--protected-path", required=True, help="A path that requires this token, e.g. /account")
    parser.add_argument("--public-key-file", help="Path to a PEM public key, for the RS256->HS256 confusion check")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    try:
        claims_result = check_jwt_claims(args.token)
    except JwtDecodeError as exc:
        print(f"ERROR: couldn't decode --token — {exc}", file=sys.stderr)
        return 1

    findings = [Finding(name="JWT claims", flagged=claims_result.flagged, detail=claims_result.detail)]

    weak_secret_result, matched_secret = check_weak_hs256_secret(args.token)
    findings.append(Finding(name="JWT weak HS256 secret", flagged=weak_secret_result.flagged, detail=weak_secret_result.detail))
    if matched_secret:
        print("⚠ Matched a weak secret from the built-in wordlist — not printing it here; check the report.", file=sys.stderr)

    alg_none_result = check_alg_none_bypass(target, args.protected_path, args.token)
    findings.append(Finding(name="JWT alg=none bypass", flagged=alg_none_result.flagged, detail=alg_none_result.detail))

    if args.public_key_file:
        public_key_pem = open(args.public_key_file, encoding="utf-8").read()
        confusion_result = check_rs256_to_hs256_confusion(target, args.protected_path, args.token, public_key_pem)
        findings.append(
            Finding(name="JWT RS256->HS256 confusion", flagged=confusion_result.flagged, detail=confusion_result.detail)
        )

    report = build_report(title="JWT Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    if report.has_flags:
        print("\n⚠ One or more JWT checks were flagged — see the report for which.")
        return 2
    print("\nNo JWT issues flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
