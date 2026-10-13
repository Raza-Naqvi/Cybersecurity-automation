from security_toolkit.orchestrator import plan_run


def _plan(tmp_path, **overrides):
    defaults = dict(
        has_credentials=False,
        register_url=None,
        protected_path=None,
        logout_path=None,
        idor_cases_path=None,
        injection_points_path=None,
        upload_cases_path=None,
        business_logic_cases_path=None,
    )
    defaults.update(overrides)
    return plan_run(**defaults)


def test_no_credentials_no_register_url_skips_everything_account_related(tmp_path):
    plan = _plan(tmp_path)
    assert plan.create_accounts is False
    assert plan.run_auth_session is False
    assert plan.run_idor is False
    assert "account creation" in plan.skip_reasons
    assert "auth/session test" in plan.skip_reasons
    assert "IDOR test" in plan.skip_reasons


def test_no_credentials_with_register_url_plans_to_create_accounts(tmp_path):
    plan = _plan(tmp_path, register_url="https://x.test/register")
    assert plan.create_accounts is True
    assert plan.needs_account_creation_confirmation is True
    assert "account creation" not in plan.skip_reasons


def test_existing_credentials_skip_account_creation(tmp_path):
    plan = _plan(tmp_path, has_credentials=True)
    assert plan.create_accounts is False
    assert plan.needs_account_creation_confirmation is False


def test_accounts_available_but_no_protected_path_skips_auth_session(tmp_path):
    plan = _plan(tmp_path, has_credentials=True)
    assert plan.run_auth_session is False
    assert "no --protected-path" in plan.skip_reasons["auth/session test"]


def test_accounts_available_with_paths_runs_auth_session(tmp_path):
    plan = _plan(tmp_path, has_credentials=True, protected_path="/account", logout_path="/logout")
    assert plan.run_auth_session is True
    assert "auth/session test" not in plan.skip_reasons


def test_idor_runs_only_when_accounts_available_and_cases_file_exists(tmp_path):
    cases_path = tmp_path / "idor_cases.json"
    cases_path.write_text("{}")

    plan_no_accounts = _plan(tmp_path, has_credentials=False, idor_cases_path=cases_path)
    assert plan_no_accounts.run_idor is False

    plan_no_file = _plan(tmp_path, has_credentials=True, idor_cases_path=tmp_path / "missing.json")
    assert plan_no_file.run_idor is False

    plan_both = _plan(tmp_path, has_credentials=True, idor_cases_path=cases_path)
    assert plan_both.run_idor is True


def test_injection_upload_business_logic_run_independently_of_accounts(tmp_path):
    injection_path = tmp_path / "injection.json"
    injection_path.write_text("{}")

    plan = _plan(tmp_path, has_credentials=False, injection_points_path=injection_path)

    assert plan.run_injection is True
    assert plan.run_upload is False
    assert plan.run_business_logic is False
    assert "upload test" in plan.skip_reasons
    assert "business logic test" in plan.skip_reasons


def test_infra_always_runs(tmp_path):
    plan = _plan(tmp_path)
    assert plan.run_infra is True


def test_ssrf_runs_whenever_injection_runs(tmp_path):
    injection_path = tmp_path / "injection.json"
    injection_path.write_text("{}")

    plan_with_points = _plan(tmp_path, injection_points_path=injection_path)
    assert plan_with_points.run_ssrf is True

    plan_without_points = _plan(tmp_path)
    assert plan_without_points.run_ssrf is False
    assert "SSRF test" in plan_without_points.skip_reasons
