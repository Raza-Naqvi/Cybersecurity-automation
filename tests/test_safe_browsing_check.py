from unittest.mock import MagicMock, patch

import pytest
import requests

from security_toolkit.config import Target
from security_toolkit.recon.safe_browsing_check import check_safe_browsing


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


def test_check_safe_browsing_flags_matches(target):
    response_json = {
        "matches": [
            {"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threat": {"url": "https://staging.example.com"}}
        ]
    }
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: response_json)
        result = check_safe_browsing(target, api_key="fake-key")

    assert result.flagged is True
    assert "MALWARE" in result.threat_types
    assert "MALWARE" in result.detail


def test_check_safe_browsing_no_matches_not_flagged(target):
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {})
        result = check_safe_browsing(target, api_key="fake-key")

    assert result.flagged is False
    assert result.threat_types == ()
    assert "No threats" in result.detail


def test_check_safe_browsing_sends_targets_base_url_and_key(target):
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {})
        check_safe_browsing(target, api_key="fake-key")

    call = mock_post.call_args
    assert call.kwargs["params"] == {"key": "fake-key"}
    body = call.kwargs["json"]
    assert body["threatInfo"]["threatEntries"] == [{"url": "https://staging.example.com"}]
    assert "MALWARE" in body["threatInfo"]["threatTypes"]


def test_check_safe_browsing_missing_api_key_flagged_with_fix_hint(target):
    result = check_safe_browsing(target, api_key=None)

    assert result.flagged is True
    assert result.succeeded is False
    assert "GOOGLE_SAFE_BROWSING_API_KEY" in result.detail


def test_check_safe_browsing_http_error_flagged_not_treated_as_clean(target):
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=400, text="API key not valid", json=lambda: {})
        result = check_safe_browsing(target, api_key="bad-key")

    assert result.flagged is True
    assert result.succeeded is False
    assert "400" in result.detail


def test_check_safe_browsing_network_error_flagged(target):
    with patch("requests.post", side_effect=requests.RequestException("boom")):
        result = check_safe_browsing(target, api_key="fake-key")

    assert result.flagged is True
    assert result.succeeded is False
    assert "boom" in result.detail


def test_check_safe_browsing_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(RuntimeError):
        check_safe_browsing(target_no_url, api_key="fake-key")
