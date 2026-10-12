from unittest.mock import MagicMock

import pytest

from security_toolkit.config import Credentials, Target
from security_toolkit.recon.session_testing import (
    check_login_rate_limiting,
    check_logout_invalidation,
    check_session_fixation,
)


@pytest.fixture
def target():
    return Target(
        name="staging",
        type="custom",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com",
        known_admin_logins=(),
        notes="",
        auth=None,
    )


@pytest.fixture
def creds():
    return Credentials(username="idor_user_a", password="pw")


def test_session_fixation_flags_unchanged_cookie(target, creds, monkeypatch):
    fake_session = MagicMock()
    fake_session.cookies = {"PHPSESSID": "same-id"}
    monkeypatch.setattr("requests.Session", lambda: fake_session)

    provider = MagicMock()
    provider.login.return_value = MagicMock(logged_in=True, status_code=200)

    result = check_session_fixation(target, provider, creds)

    assert result.flagged is True


def test_session_fixation_ok_when_cookie_changes(target, creds, monkeypatch):
    class FakeSession:
        def __init__(self):
            self.cookies = {"PHPSESSID": "pre"}

        def get(self, *args, **kwargs):
            return MagicMock(status_code=200)

    fake_session = FakeSession()
    monkeypatch.setattr("requests.Session", lambda: fake_session)

    def fake_login(session, credentials):
        session.cookies = {"PHPSESSID": "post"}  # server rotates the session id on login
        return MagicMock(logged_in=True, status_code=200)

    provider = MagicMock()
    provider.login.side_effect = fake_login

    result = check_session_fixation(target, provider, creds)

    assert result.flagged is False
    assert result.session_cookie_changed is True


def test_session_fixation_not_flagged_when_login_fails(target, creds, monkeypatch):
    fake_session = MagicMock()
    fake_session.cookies = {"PHPSESSID": "same-id"}
    monkeypatch.setattr("requests.Session", lambda: fake_session)

    provider = MagicMock()
    provider.login.return_value = MagicMock(logged_in=False, status_code=401)

    result = check_session_fixation(target, provider, creds)

    assert result.flagged is False


def test_logout_invalidation_flags_still_working_session(target):
    session = MagicMock()
    # calls: before-logout GET, logout GET, after-logout GET
    session.get.side_effect = [MagicMock(status_code=200), MagicMock(status_code=302), MagicMock(status_code=200)]

    result = check_logout_invalidation(target, session, "/logout", "/account")

    assert result.flagged is True
    assert result.before_logout_status == 200
    assert result.after_logout_status == 200


def test_logout_invalidation_ok_when_session_rejected(target):
    session = MagicMock()
    session.get.side_effect = [MagicMock(status_code=200), MagicMock(status_code=302), MagicMock(status_code=401)]

    result = check_logout_invalidation(target, session, "/logout", "/account")

    assert result.flagged is False


def test_logout_invalidation_uses_post_when_requested(target):
    session = MagicMock()
    session.get.side_effect = [MagicMock(status_code=200), MagicMock(status_code=401)]
    session.post.return_value = MagicMock(status_code=200)

    check_logout_invalidation(target, session, "/logout", "/account", logout_method="post")

    session.post.assert_called_once()


def test_check_login_rate_limiting_flags_when_no_429_seen(creds):
    provider = MagicMock()
    provider.login.return_value = MagicMock(status_code=401)

    result = check_login_rate_limiting(provider, creds, max_attempts=5)

    assert result.flagged is True
    assert result.blocked is False
    assert len(result.status_codes) == 5


def test_check_login_rate_limiting_not_flagged_when_429_seen(creds):
    provider = MagicMock()
    provider.login.side_effect = [MagicMock(status_code=401)] * 3 + [MagicMock(status_code=429)] * 2

    result = check_login_rate_limiting(provider, creds, max_attempts=5)

    assert result.flagged is False
    assert result.blocked is True


def test_check_login_rate_limiting_rejects_non_positive_attempts(creds):
    provider = MagicMock()
    with pytest.raises(ValueError):
        check_login_rate_limiting(provider, creds, max_attempts=0)
