from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.recon.provision import generate_test_password, register_via_api, register_via_form

LARAVEL_REGISTER_HTML = """
<html><body>
<form method="POST" action="/register">
    <input type="hidden" name="_token" value="csrf-abc">
    <input type="text" name="name" required>
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <input type="password" name="password_confirmation" required>
    <input type="checkbox" name="accept_terms" value="1">
    <button type="submit">Register</button>
</form>
</body></html>
"""


def test_generate_test_password_has_requested_length():
    password = generate_test_password(16)
    assert len(password) == 16


def test_generate_test_password_rejects_short_length():
    with pytest.raises(ValueError):
        generate_test_password(4)


def test_generate_test_password_is_random_each_call():
    assert generate_test_password() != generate_test_password()


def test_register_via_api_success():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=201)
        result = register_via_api("https://x.test/register", {"email": "a@test.com", "password": "pw"})
    assert result.email == "a@test.com"


def test_register_via_api_failure_raises():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=422, text="validation error")
        with pytest.raises(RuntimeError, match="registration failed"):
            register_via_api("https://x.test/register", {"email": "a@test.com", "password": "pw"})


def test_register_via_form_fills_and_submits_detected_fields():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, text=LARAVEL_REGISTER_HTML)
        session.post.return_value = MagicMock(status_code=302, text="")
        mock_session_cls.return_value = session

        result = register_via_form(
            "https://x.test/register", email="a@test.com", identity_value="IDOR User A", password="generated-pw"
        )

    sent = session.post.call_args.kwargs["data"]
    assert sent["_token"] == "csrf-abc"
    assert sent["email"] == "a@test.com"
    assert sent["name"] == "IDOR User A"
    assert sent["password"] == "generated-pw"
    assert sent["password_confirmation"] == "generated-pw"
    assert sent["accept_terms"] == "1"
    assert result.email == "a@test.com"
    assert result.password == "generated-pw"


def test_register_via_form_generates_password_when_not_given():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, text=LARAVEL_REGISTER_HTML)
        session.post.return_value = MagicMock(status_code=302, text="")
        mock_session_cls.return_value = session

        result = register_via_form("https://x.test/register", email="a@test.com", identity_value="IDOR User A")

    assert len(result.password) >= 12


def test_register_via_form_raises_on_get_failure():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=404, text="")
        mock_session_cls.return_value = session

        with pytest.raises(RuntimeError, match="status 404"):
            register_via_form("https://x.test/register", email="a@test.com", identity_value="IDOR User A")


def test_register_via_form_raises_when_no_form_found():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, text="<html><body>no form here</body></html>")
        mock_session_cls.return_value = session

        with pytest.raises(RuntimeError):
            register_via_form("https://x.test/register", email="a@test.com", identity_value="IDOR User A")


def test_register_via_form_raises_on_submit_failure():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, text=LARAVEL_REGISTER_HTML)
        session.post.return_value = MagicMock(status_code=422, text="email already taken")
        mock_session_cls.return_value = session

        with pytest.raises(RuntimeError, match="registration failed"):
            register_via_form("https://x.test/register", email="a@test.com", identity_value="IDOR User A")
