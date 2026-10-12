from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.recon.provision import generate_test_password, register_via_api


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
