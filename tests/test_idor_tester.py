from unittest.mock import MagicMock

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.idor_tester import (
    IdorTestCase,
    OutOfScopeError,
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
