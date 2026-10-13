#!/usr/bin/env python3
"""CLI: Phase 4.3 black-box auth/session test for an authorized target.

Pure HTTP(S) — reuses the same `auth` block in scope.json as the IDOR
tester. Needs one valid test account (for fixation/logout) and tests a
known-bad password against it for the rate-limit check — it never
guesses at a real account.

Usage:
    python scripts/run_auth_test.py --target example-staging \\
        --protected-path /account/orders --logout-path /logout
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import Credentials, ScopeError, load_authorized_target_cli, load_test_credentials
from security_toolkit.recon.auth import AuthConfigError, AuthFailure, build_auth_provider, login
from security_toolkit.recon.jwt_testing import check_token_storage_hint
from security_toolkit.recon.session_testing import (
    check_login_rate_limiting,
    check_logout_invalidation,
    check_session_fixation,
)
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--protected-path", required=True, help="A path only a logged-in user can reach, e.g. /account")
    parser.add_argument("--logout-path", required=True, help="The logout URL path, e.g. /logout")
    parser.add_argument("--logout-method", default="get", choices=["get", "post"])
    parser.add_argument("--rate-limit-attempts", type=int, default=10)
    parser.add_argument(
        "--skip-rate-limit", action="store_true", help="Skip the repeated-bad-login check (it makes N login attempts)"
    )
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    if not target.auth:
        print(f"ERROR: target '{target.name}' has no 'auth' block in scope.json", file=sys.stderr)
        return 1

    try:
        provider = build_auth_provider(target.auth)
    except AuthConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        creds = load_test_credentials(target.name, "IDOR_USER_A")
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    findings = []

    fixation = check_session_fixation(target, provider, creds)
    findings.append(Finding(name="Session fixation", flagged=fixation.flagged, detail=fixation.detail))

    try:
        session, login_result = login(provider, creds)
    except AuthFailure as exc:
        print(f"ERROR: login failed — {exc}", file=sys.stderr)
        return 1

    storage_hint = check_token_storage_hint(
        login_result.set_cookie_headers, token_in_json_body=login_result.token is not None
    )
    findings.append(Finding(name="JWT/token storage hint", flagged=storage_hint.flagged, detail=storage_hint.detail))

    logout = check_logout_invalidation(
        target, session, args.logout_path, args.protected_path, logout_method=args.logout_method
    )
    findings.append(Finding(name="Logout invalidation", flagged=logout.flagged, detail=logout.detail))

    if not args.skip_rate_limit:
        bad_creds = Credentials(username=creds.username, password=creds.password + "-wrong")
        rate_limit = check_login_rate_limiting(provider, bad_creds, max_attempts=args.rate_limit_attempts)
        findings.append(Finding(name="Login rate limiting", flagged=rate_limit.flagged, detail=rate_limit.detail))

    report = build_report(title="Auth/Session Test", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())
