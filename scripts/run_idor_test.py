#!/usr/bin/env python3
"""CLI: Phase 4.4 two-account IDOR test, for any site type (WordPress,
Laravel, custom Node/Express — whatever `auth.type` in scope.json says).

Setup (once per target):
  1. Add an `auth` block to that target in config/scope.json — see
     src/security_toolkit/recon/auth.py's docstring for the schema.
  2. Create two disposable test accounts on staging (see
     src/security_toolkit/recon/provision.py), and put their credentials
     in .env as IDOR_USER_A_USERNAME/PASSWORD and IDOR_USER_B_USERNAME/PASSWORD.
  3. Copy config/idor_cases.example.json, fill in endpoints + an ID that
     belongs to User A, and pass its path with --cases.

Usage:
    python scripts/run_idor_test.py --target example-staging --cases config/idor_cases/example-staging.json
"""

from __future__ import annotations

import argparse
import json
import sys

from security_toolkit.config import ScopeError, load_authorized_target, load_credentials_from_env
from security_toolkit.recon.auth import AuthConfigError, AuthFailure, build_auth_provider, login
from security_toolkit.recon.idor_tester import IdorTestCase, OutOfScopeError, run_idor_suite
from security_toolkit.reporting.report import Finding, build_report, write_report


def _load_cases(path: str) -> list[IdorTestCase]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [
        IdorTestCase(name=item["name"], url_template=item["url_template"], owner_id=item["owner_id"])
        for item in data.get("cases", [])
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--cases", required=True, help="Path to a JSON file of IDOR test cases")
    args = parser.parse_args()

    try:
        target = load_authorized_target(args.target)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not target.auth:
        print(
            f"ERROR: target '{target.name}' has no 'auth' block in scope.json. "
            "See src/security_toolkit/recon/auth.py for the schema.",
            file=sys.stderr,
        )
        return 1

    try:
        provider = build_auth_provider(target.auth)
    except AuthConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        creds_a = load_credentials_from_env("IDOR_USER_A")
        creds_b = load_credentials_from_env("IDOR_USER_B")
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        session_a, _ = login(provider, creds_a)
        session_b, _ = login(provider, creds_b)
    except AuthFailure as exc:
        print(f"ERROR: login failed — {exc}", file=sys.stderr)
        return 1

    cases = _load_cases(args.cases)
    if not cases:
        print(f"ERROR: no test cases found in {args.cases}", file=sys.stderr)
        return 1

    try:
        results = run_idor_suite(target, session_a, session_b, cases)
    except OutOfScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    findings = [
        Finding(name=result.name, flagged=result.flagged, detail=f"{result.url}\n{result.detail}")
        for result in results
    ]
    report = build_report(title="IDOR Test", target=target.name, findings=findings)
    json_path, html_path = write_report(report)

    print(f"Report written:\n  {json_path}\n  {html_path}")
    if report.has_flags:
        print("\n⚠ One or more endpoints are flagged for IDOR — see the report for which.")
        return 2
    print("\nNo IDOR flagged by this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
