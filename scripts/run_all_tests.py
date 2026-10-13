#!/usr/bin/env python3
"""CLI: run every black-box check for one target in a single command.

Figures out everything up front — whether test accounts need creating,
which case files exist — and asks its one possible question (permission
to create real accounts on the live site) immediately, before anything
runs. After that, it runs straight through with no further prompts:
account creation (if needed) -> recon -> auth/session -> IDOR ->
injection -> upload -> business-logic -> infra, skipping whichever
checks aren't set up for this target, and says exactly why.

Each check still uploads its own report to Cloudinary (see
reporting/cloud_report.py) and indexes it in MongoDB; this script just
sequences them and prints one consolidated summary with every link.

Usage:
    python scripts/run_all_tests.py --target cheerlytics \\
        --register-url https://.../register \\
        --protected-path /dashboard --logout-path /logout
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from security_toolkit.config import REPO_ROOT, load_authorized_target_cli
from security_toolkit.credentials_db import load_credentials
from security_toolkit.orchestrator import RunPlan, plan_run

PYTHON = sys.executable
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _default_case_path(folder: str, target_name: str) -> Path:
    return REPO_ROOT / "config" / folder / f"{target_name}.json"


def _print_plan(plan: RunPlan) -> None:
    print("Plan:")
    print(f"  {'create test accounts' if plan.create_accounts else 'skip account creation'}"
          + ("" if plan.create_accounts else f"  ({plan.skip_reasons.get('account creation', 'already have accounts')})"))
    for step, will_run in (
        ("auth/session test", plan.run_auth_session),
        ("IDOR test", plan.run_idor),
        ("injection test", plan.run_injection),
        ("SSRF test", plan.run_ssrf),
        ("upload test", plan.run_upload),
        ("business logic test", plan.run_business_logic),
    ):
        if will_run:
            print(f"  run {step}")
        else:
            print(f"  skip {step}  ({plan.skip_reasons.get(step, 'not configured')})")
    print("  run recon")
    print("  run infra test")
    print()


def _run_script(script_name: str, extra_args: list[str]) -> int:
    cmd = [PYTHON, str(SCRIPTS_DIR / script_name), *extra_args]
    print(f"\n--- {script_name} {' '.join(extra_args)} ---")
    return subprocess.run(cmd).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument("--register-url", help="Public registration URL, to auto-create test accounts if none exist yet")
    parser.add_argument("--protected-path", help="A logged-in-only path, for the auth/session test")
    parser.add_argument("--logout-path", help="The logout path, for the auth/session test")
    parser.add_argument("--logout-method", default="get", choices=["get", "post"])
    parser.add_argument("--rate-limit-attempts", type=int, default=10)
    parser.add_argument("--skip-rate-limit", action="store_true")
    parser.add_argument("--skip-subdomain-enum", action="store_true", help="Skip the subfinder check during recon")
    parser.add_argument("--skip-dir-enum", action="store_true", help="Skip the dirsearch check during recon")
    parser.add_argument("--yes", action="store_true", help="Answer the account-creation confirmation yes automatically")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    try:
        has_credentials = (
            load_credentials(target.name, "IDOR_USER_A") is not None
            and load_credentials(target.name, "IDOR_USER_B") is not None
        )
    except Exception as exc:  # noqa: BLE001 — any Mongo connection/auth failure, not just a missing doc
        print(f"ERROR: could not reach the MongoDB credential store: {exc}", file=sys.stderr)
        print("Run scripts/doctor.py to check your MONGODB_URI, or fix the connection and retry.", file=sys.stderr)
        return 1

    plan = plan_run(
        has_credentials=has_credentials,
        register_url=args.register_url,
        protected_path=args.protected_path,
        logout_path=args.logout_path,
        idor_cases_path=_default_case_path("idor_cases", target.name),
        injection_points_path=_default_case_path("injection_points", target.name),
        upload_cases_path=_default_case_path("upload_cases", target.name),
        business_logic_cases_path=_default_case_path("business_logic_cases", target.name),
    )

    _print_plan(plan)

    # The one question this script ever asks — right here, before anything runs.
    if plan.needs_account_creation_confirmation and not args.yes:
        confirm = input(
            f"This will create 2 real accounts on {target.base_url} via {args.register_url}. Continue? [y/N]: "
        ).strip().lower()
        if confirm != "y":
            print("Aborted — nothing has run yet.")
            return 1

    exit_codes: dict[str, int] = {}

    if plan.create_accounts:
        exit_codes["account creation"] = _run_script(
            "provision_test_accounts.py",
            ["--target", target.name, "--register-url", args.register_url, "--yes"],
        )
        if exit_codes["account creation"] != 0:
            print("Account creation failed — auth/session and IDOR tests will be skipped for this run.")
            plan = replace(
                plan,
                run_auth_session=False,
                run_idor=False,
                skip_reasons={
                    **plan.skip_reasons,
                    "auth/session test": "account creation failed",
                    "IDOR test": "account creation failed",
                },
            )

    recon_args = ["--target", target.name]
    if args.skip_subdomain_enum:
        recon_args.append("--skip-subdomain-enum")
    if args.skip_dir_enum:
        recon_args.append("--skip-dir-enum")
    exit_codes["recon"] = _run_script("run_recon.py", recon_args)

    if plan.run_auth_session:
        auth_args = [
            "--target", target.name,
            "--protected-path", args.protected_path,
            "--logout-path", args.logout_path,
            "--logout-method", args.logout_method,
            "--rate-limit-attempts", str(args.rate_limit_attempts),
        ]
        if args.skip_rate_limit:
            auth_args.append("--skip-rate-limit")
        exit_codes["auth/session test"] = _run_script("run_auth_test.py", auth_args)

    if plan.run_idor:
        exit_codes["IDOR test"] = _run_script(
            "run_idor_test.py", ["--target", target.name, "--cases", str(_default_case_path("idor_cases", target.name))]
        )

    if plan.run_injection:
        exit_codes["injection test"] = _run_script(
            "run_injection_test.py",
            ["--target", target.name, "--points", str(_default_case_path("injection_points", target.name))],
        )

    if plan.run_ssrf:
        exit_codes["SSRF test"] = _run_script(
            "run_ssrf_test.py",
            ["--target", target.name, "--points", str(_default_case_path("injection_points", target.name))],
        )

    if plan.run_upload:
        exit_codes["upload test"] = _run_script(
            "run_upload_test.py", ["--target", target.name, "--cases", str(_default_case_path("upload_cases", target.name))]
        )

    if plan.run_business_logic:
        exit_codes["business logic test"] = _run_script(
            "run_business_logic_test.py",
            ["--target", target.name, "--cases", str(_default_case_path("business_logic_cases", target.name))],
        )

    exit_codes["infra test"] = _run_script("run_infra_test.py", ["--target", target.name])

    _run_script("generate_findings_report.py", ["--target", target.name, "--upload"])

    print("\n=== Summary ===")
    for name, code in exit_codes.items():
        status = {0: "clean", 2: "flagged"}.get(code, f"error (exit {code})")
        print(f"  {name}: {status}")
    for step, reason in plan.skip_reasons.items():
        if step not in exit_codes:
            print(f"  {step}: skipped — {reason}")

    if any(code not in (0, 2) for code in exit_codes.values()):
        return 1
    if any(code == 2 for code in exit_codes.values()):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
