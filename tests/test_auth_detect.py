from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.recon.auth_detect import AuthDetectionError, detect_auth_config

LARAVEL_LOGIN_HTML = """
<html><body>
<form method="POST" action="/login">
    <input type="hidden" name="_token" value="abc123" autocomplete="off">
    <div class="form-group">
        <label>Email Address</label>
        <input type="email" class="form-control" name="email" required autofocus>
    </div>
    <div class="form-group">
        <input type="password" class="form-control" name="password" required>
    </div>
    <button type="submit">Login</button>
</form>
</body></html>
"""

WORDPRESS_LOGIN_HTML = """
<html><body>
<form name="loginform" id="loginform" action="https://x.test/wp-login.php" method="post">
    <input type="text" name="log" id="user_login" class="input" value="" size="20">
    <input type="password" name="pwd" id="user_pass" class="input" value="" size="20">
    <input type="hidden" name="redirect_to" value="https://x.test/wp-admin/">
    <input type="hidden" name="testcookie" value="1">
    <input type="submit" name="wp-submit" value="Log In">
</form>
</body></html>
"""

NO_FORM_HTML = "<html><body><p>This is a JS-rendered app shell.</p></body></html>"

NO_PASSWORD_FORM_HTML = """
<html><body>
<form method="GET" action="/search">
    <input type="text" name="q">
    <button type="submit">Search</button>
</form>
</body></html>
"""


def test_detect_auth_config_laravel_form():
    with patch("requests.get", return_value=MagicMock(status_code=200, text=LARAVEL_LOGIN_HTML)):
        block = detect_auth_config("https://x.test/login")

    assert block == {
        "type": "form_session",
        "login_url": "https://x.test/login",
        "username_field": "email",
        "password_field": "password",
        "csrf": {"page_url": "https://x.test/login", "field_name": "_token"},
    }


def test_detect_auth_config_wordpress_form():
    with patch("requests.get", return_value=MagicMock(status_code=200, text=WORDPRESS_LOGIN_HTML)):
        block = detect_auth_config("https://x.test/wp-login.php")

    assert block == {"type": "wordpress", "login_url": "https://x.test/wp-login.php"}


def test_detect_auth_config_raises_when_no_form_present():
    with patch("requests.get", return_value=MagicMock(status_code=200, text=NO_FORM_HTML)):
        with pytest.raises(AuthDetectionError):
            detect_auth_config("https://x.test/login")


def test_detect_auth_config_raises_when_no_password_field():
    with patch("requests.get", return_value=MagicMock(status_code=200, text=NO_PASSWORD_FORM_HTML)):
        with pytest.raises(AuthDetectionError):
            detect_auth_config("https://x.test/login")


def test_detect_auth_config_raises_on_http_error():
    with patch("requests.get", return_value=MagicMock(status_code=404, text="")):
        with pytest.raises(AuthDetectionError):
            detect_auth_config("https://x.test/login")


def test_detect_auth_config_falls_back_to_username_when_no_known_field_name():
    html = """
    <form method="POST" action="/login">
        <input type="hidden" name="_token" value="abc">
        <input type="text" name="handle">
        <input type="password" name="secret">
    </form>
    """
    with patch("requests.get", return_value=MagicMock(status_code=200, text=html)):
        block = detect_auth_config("https://x.test/login")

    assert block["username_field"] == "handle"
    assert block["password_field"] == "secret"
