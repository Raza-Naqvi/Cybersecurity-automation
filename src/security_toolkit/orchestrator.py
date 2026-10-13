"""Pure decision logic behind `scripts/run_all_tests.py`: given what's
already set up for a target (credentials stored? case files present?),
decide what to run, what to skip, and why — before anything actually
runs. This is what lets the script print its whole plan and ask its one
possible question (account creation) right at the start, instead of
discovering mid-run that something needs confirming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RunPlan:
    create_accounts: bool
    run_auth_session: bool
    run_idor: bool
    run_injection: bool
    run_ssrf: bool
    run_upload: bool
    run_business_logic: bool
    run_infra: bool
    skip_reasons: dict[str, str] = field(default_factory=dict)

    @property
    def needs_account_creation_confirmation(self) -> bool:
        return self.create_accounts


def plan_run(
    has_credentials: bool,
    register_url: str | None,
    protected_path: str | None,
    logout_path: str | None,
    idor_cases_path: Path | None,
    injection_points_path: Path | None,
    upload_cases_path: Path | None,
    business_logic_cases_path: Path | None,
) -> RunPlan:
    skip_reasons: dict[str, str] = {}

    create_accounts = not has_credentials and bool(register_url)
    accounts_will_exist = has_credentials or create_accounts
    if not accounts_will_exist:
        skip_reasons["account creation"] = "no test accounts stored and no --register-url given"

    run_auth_session = accounts_will_exist and bool(protected_path) and bool(logout_path)
    if not accounts_will_exist:
        skip_reasons["auth/session test"] = "no test accounts available"
    elif not run_auth_session:
        skip_reasons["auth/session test"] = "no --protected-path/--logout-path given"

    run_idor = accounts_will_exist and idor_cases_path is not None and idor_cases_path.exists()
    if not accounts_will_exist:
        skip_reasons["IDOR test"] = "no test accounts available"
    elif not run_idor:
        skip_reasons["IDOR test"] = f"no {idor_cases_path} found"

    run_injection = injection_points_path is not None and injection_points_path.exists()
    if not run_injection:
        skip_reasons["injection test"] = f"no {injection_points_path} found"

    # SSRF reuses the same injection-points config (same shape: a path +
    # parameter to probe) — no separate setup needed.
    run_ssrf = run_injection
    if not run_ssrf:
        skip_reasons["SSRF test"] = f"no {injection_points_path} found"

    run_upload = upload_cases_path is not None and upload_cases_path.exists()
    if not run_upload:
        skip_reasons["upload test"] = f"no {upload_cases_path} found"

    run_business_logic = business_logic_cases_path is not None and business_logic_cases_path.exists()
    if not run_business_logic:
        skip_reasons["business logic test"] = f"no {business_logic_cases_path} found"

    return RunPlan(
        create_accounts=create_accounts,
        run_auth_session=run_auth_session,
        run_idor=run_idor,
        run_injection=run_injection,
        run_ssrf=run_ssrf,
        run_upload=run_upload,
        run_business_logic=run_business_logic,
        run_infra=True,
        skip_reasons=skip_reasons,
    )
