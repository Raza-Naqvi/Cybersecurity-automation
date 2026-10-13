from unittest.mock import MagicMock, patch

import pytest
import requests

from security_toolkit.config import Target
from security_toolkit.recon.injection_testing import InjectionPoint
from security_toolkit.recon.ssrf_testing import (
    CallbackServiceError,
    callback_url,
    check_ssrf,
    create_callback_token,
    poll_for_hit,
)


@pytest.fixture
def target():
    return Target(
        name="staging", type="custom", environment="staging", wp_path=None,
        base_url="https://staging.example.com", known_admin_logins=(), notes="", auth=None,
    )


def test_create_callback_token_returns_uuid():
    with patch("requests.post", return_value=MagicMock(status_code=200, json=lambda: {"uuid": "abc-123"})):
        token = create_callback_token()
    assert token == "abc-123"


def test_create_callback_token_raises_on_service_failure():
    with patch("requests.post", side_effect=requests.ConnectionError("down")):
        with pytest.raises(CallbackServiceError):
            create_callback_token()


def test_callback_url_builds_expected_url():
    assert callback_url("abc-123") == "https://webhook.site/abc-123"


def test_poll_for_hit_returns_true_when_data_present():
    with patch("requests.get", return_value=MagicMock(status_code=200, json=lambda: {"data": [{"ip": "1.2.3.4"}]})):
        assert poll_for_hit("abc-123", max_wait=1, poll_interval=0.1) is True


def test_poll_for_hit_returns_false_when_no_data_within_deadline():
    with patch("requests.get", return_value=MagicMock(status_code=200, json=lambda: {"data": []})):
        assert poll_for_hit("abc-123", max_wait=0.3, poll_interval=0.1) is False


def test_poll_for_hit_tolerates_transient_errors_and_keeps_trying():
    responses = [
        requests.ConnectionError("blip"),
        MagicMock(status_code=200, json=lambda: {"data": [{"ip": "1.2.3.4"}]}),
    ]
    with patch("requests.get", side_effect=responses):
        assert poll_for_hit("abc-123", max_wait=2, poll_interval=0.1) is True


def test_check_ssrf_flags_confirmed_callback(target):
    point = InjectionPoint(name="webhook url", path="/webhooks/register", method="post", param_name="url", param_location="json")
    with (
        patch("security_toolkit.recon.ssrf_testing.create_callback_token", return_value="tok-1"),
        patch("requests.post", return_value=MagicMock(status_code=200)),
        patch("security_toolkit.recon.ssrf_testing.poll_for_hit", return_value=True),
    ):
        result = check_ssrf(target, point)

    assert result.flagged is True
    assert "tok-1" in result.callback_url


def test_check_ssrf_not_flagged_when_no_callback_received(target):
    point = InjectionPoint(name="webhook url", path="/webhooks/register", method="post", param_name="url", param_location="json")
    with (
        patch("security_toolkit.recon.ssrf_testing.create_callback_token", return_value="tok-1"),
        patch("requests.post", return_value=MagicMock(status_code=200)),
        patch("security_toolkit.recon.ssrf_testing.poll_for_hit", return_value=False),
    ):
        result = check_ssrf(target, point)

    assert result.flagged is False
