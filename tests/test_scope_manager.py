import pytest

from security_toolkit.scope_manager import build_auth_block


def test_build_auth_block_wordpress():
    block = build_auth_block("wordpress", login_url="https://x.test/wp-login.php")
    assert block == {"type": "wordpress", "login_url": "https://x.test/wp-login.php"}


def test_build_auth_block_form_session_with_csrf():
    block = build_auth_block(
        "form_session",
        login_url="https://x.test/login",
        username_field="email",
        csrf_page_url="https://x.test/login",
        csrf_field_name="_token",
    )
    assert block["csrf"] == {"page_url": "https://x.test/login", "field_name": "_token"}
    assert block["username_field"] == "email"


def test_build_auth_block_form_session_without_csrf_omits_key():
    block = build_auth_block("form_session", login_url="https://x.test/login")
    assert "csrf" not in block


def test_build_auth_block_json_token():
    block = build_auth_block("json_token", login_url="https://x.test/api/login", token_path="data.token")
    assert block["token_path"] == "data.token"
    assert block["header_prefix"] == "Bearer "


def test_build_auth_block_rejects_unknown_type():
    with pytest.raises(ValueError):
        build_auth_block("sso-magic", login_url="https://x.test/login")


def test_build_auth_block_requires_login_url():
    with pytest.raises(ValueError):
        build_auth_block("wordpress", login_url="")
