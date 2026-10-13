from unittest.mock import MagicMock

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.idor_tester import (
    IdorTestCase,
    OutOfScopeError,
    check_idor_case_rate_limiting,
    check_sequential_id_enumeration,
    require_in_scope,
    run_idor_test,
)


@pytest.fixture
def staging_target():
    return Target(
        name="staging",
        type="custom",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com",
        known_admin_logins=(),
        notes="",
    )


def test_require_in_scope_allows_matching_base_url(staging_target):
    require_in_scope("https://staging.example.com/api/orders/5", staging_target)  # no raise


def test_require_in_scope_rejects_other_host(staging_target):
    with pytest.raises(OutOfScopeError):
        require_in_scope("https://production.example.com/api/orders/5", staging_target)


def test_run_idor_test_flags_successful_cross_account_access(staging_target):
    session_owner = MagicMock()
    session_owner.get.return_value = MagicMock(status_code=200)
    session_other = MagicMock()
    session_other.get.return_value = MagicMock(status_code=200)

    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="42")
    result = run_idor_test(staging_target, session_owner, session_other, case)

    assert result.flagged is True
    assert result.other_user_status == 200


def test_run_idor_test_passes_when_other_user_denied(staging_target):
    session_owner = MagicMock()
    session_owner.get.return_value = MagicMock(status_code=200)
    session_other = MagicMock()
    session_other.get.return_value = MagicMock(status_code=403)

    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="42")
    result = run_idor_test(staging_target, session_owner, session_other, case)

    assert result.flagged is False


def test_check_sequential_id_enumeration_flags_accessible_neighbors(staging_target):
    session_other = MagicMock()
    session_other.get.return_value = MagicMock(status_code=200)

    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="42")
    result = check_sequential_id_enumeration(staging_target, session_other, case, range_before=2, range_after=2)

    assert result.flagged is True
    assert result.tested_ids == ("40", "41", "43", "44")
    assert result.accessible_ids == ("40", "41", "43", "44")


def test_check_sequential_id_enumeration_not_flagged_when_neighbors_denied(staging_target):
    session_other = MagicMock()
    session_other.get.return_value = MagicMock(status_code=403)

    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="42")
    result = check_sequential_id_enumeration(staging_target, session_other, case, range_before=2, range_after=2)

    assert result.flagged is False
    assert result.accessible_ids == ()


def test_check_sequential_id_enumeration_skips_non_integer_ids(staging_target):
    session_other = MagicMock()
    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="not-a-number")

    result = check_sequential_id_enumeration(staging_target, session_other, case)

    assert result.flagged is False
    assert result.tested_ids == ()
    assert "skipped" in result.detail
    session_other.get.assert_not_called()


def test_check_idor_case_rate_limiting_flags_when_no_429(staging_target):
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    case = IdorTestCase(name="order lookup", url_template="/api/orders/{id}", owner_id="42")

    result = check_idor_case_rate_limiting(staging_target, session, case, max_attempts=3)

    assert result.flagged is True
    assert session.get.call_count == 3
