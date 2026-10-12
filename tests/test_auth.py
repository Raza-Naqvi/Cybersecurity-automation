from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Credentials
from security_toolkit.recon.auth import (
    AuthConfigError,
    AuthFailure,
    FormSessionAuthProvider,
    JsonTokenAuthProvider,
    _extract_csrf_token,
    _lookup_path,
    build_auth_provider,
    login,
    wordpress_auth_provider,
)


def test_lookup_path_resolves_nested_field():
    assert _lookup_path({"data": {"token": "abc"}}, "data.token") == "abc"


def test_lookup_path_raises_on_missing_field():
    with pytest.raises(AuthFailure):
        _lookup_path({"data": {}}, "data.token")


def test_extract_csrf_token_name_before_value():
    html = '<input type="hidden" name="_token" value="XYZ123">'
    assert _extract_csrf_token(html, "_token") == "XYZ123"


def test_extract_csrf_token_value_before_name():
    html = '<input value="XYZ123" name="_token" type="hidden">'
    assert _extract_csrf_token(html, "_token") == "XYZ123"


def test_extract_csrf_token_missing_raises():
    with pytest.raises(AuthFailure):
        _extract_csrf_token("<form></form>", "_token")


def test_wordpress_auth_provider_uses_log_pwd_fields():
    provider = wordpress_auth_provider("https://staging.test/wp-login.php")
    assert provider.username_field == "log"
    assert provider.password_field == "pwd"
    assert provider.login_url == "https://staging.test/wp-login.php"


def test_form_session_login_succeeds_with_cookie():
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=200)
    session.cookies = {"session": "abc"}

    provider = FormSessionAuthProvider(login_url="https://staging.test/login")
    result = provider.login(session, Credentials(username="a", password="b"))

    assert result.logged_in is True
    session.post.assert_called_once()


def test_form_session_login_fails_without_cookie():
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=200)
    session.cookies = {}

    provider = FormSessionAuthProvider(login_url="https://staging.test/login")
    result = provider.login(session, Credentials(username="a", password="b"))

    assert result.logged_in is False


def test_form_session_login_fetches_csrf_token_first():
    session = MagicMock()
    session.get.return_value = MagicMock(text='<input name="_token" value="TOK">')
    session.post.return_value = MagicMock(status_code=200)
    session.cookies = {"laravel_session": "abc"}

    provider = FormSessionAuthProvider(
        login_url="https://staging.test/login",
        username_field="email",
        password_field="password",
        csrf_page_url="https://staging.test/login",
        csrf_field_name="_token",
    )
    result = provider.login(session, Credentials(username="a@test.com", password="b"))

    assert result.logged_in is True
    sent_payload = session.post.call_args.kwargs["data"]
    assert sent_payload["_token"] == "TOK"


def test_json_token_login_sets_auth_header():
    session = MagicMock()
    session.headers = {}
    session.post.return_value = MagicMock(status_code=200, json=lambda: {"data": {"token": "jwt-abc"}})

    provider = JsonTokenAuthProvider(login_url="https://staging.test/api/login", token_path="data.token")
    result = provider.login(session, Credentials(username="a", password="b"))

    assert result.logged_in is True
    assert session.headers["Authorization"] == "Bearer jwt-abc"


def test_json_token_login_fails_on_http_error():
    session = MagicMock()
    session.headers = {}
    session.post.return_value = MagicMock(status_code=401)

    provider = JsonTokenAuthProvider(login_url="https://staging.test/api/login")
    result = provider.login(session, Credentials(username="a", password="b"))

    assert result.logged_in is False
    assert result.status_code == 401


def test_build_auth_provider_wordpress():
    provider = build_auth_provider({"type": "wordpress", "login_url": "https://x.test/wp-login.php"})
    assert isinstance(provider, FormSessionAuthProvider)
    assert provider.username_field == "log"


def test_build_auth_provider_form_session_with_csrf():
    provider = build_auth_provider(
        {
            "type": "form_session",
            "login_url": "https://x.test/login",
            "username_field": "email",
            "csrf": {"page_url": "https://x.test/login", "field_name": "_token"},
        }
    )
    assert provider.csrf_field_name == "_token"


def test_build_auth_provider_json_token():
    provider = build_auth_provider({"type": "json_token", "login_url": "https://x.test/api/login"})
    assert isinstance(provider, JsonTokenAuthProvider)


def test_build_auth_provider_rejects_unknown_type():
    with pytest.raises(AuthConfigError):
        build_auth_provider({"type": "sso-magic"})


def test_build_auth_provider_rejects_missing_login_url():
    with pytest.raises(AuthConfigError):
        build_auth_provider({"type": "json_token"})


def test_login_raises_auth_failure_on_bad_credentials():
    provider = MagicMock()
    provider.login.return_value = MagicMock(logged_in=False, detail="bad creds")
    with patch("requests.Session"):
        with pytest.raises(AuthFailure):
            login(provider, Credentials(username="a", password="wrong"))


def test_login_returns_session_on_success():
    provider = MagicMock()
    provider.login.return_value = MagicMock(logged_in=True, detail="ok")
    session, result = login(provider, Credentials(username="a", password="b"))
    assert result.logged_in is True
