from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.recon.rate_limit_check import check_rate_limiting, check_rate_limiting_for_url


def test_check_rate_limiting_flags_when_no_429_seen():
    send = MagicMock(return_value=MagicMock(status_code=200))
    result = check_rate_limiting("test action", send, max_attempts=5)
    assert result.flagged is True
    assert result.blocked is False
    assert send.call_count == 5


def test_check_rate_limiting_not_flagged_when_429_seen():
    send = MagicMock(side_effect=[MagicMock(status_code=200)] * 3 + [MagicMock(status_code=429)] * 2)
    result = check_rate_limiting("test action", send, max_attempts=5)
    assert result.flagged is False
    assert result.blocked is True


def test_check_rate_limiting_rejects_non_positive_attempts():
    with pytest.raises(ValueError):
        check_rate_limiting("test", MagicMock(), max_attempts=0)


def test_check_rate_limiting_for_url_uses_get_by_default():
    with patch("requests.get", return_value=MagicMock(status_code=200)) as mock_get:
        result = check_rate_limiting_for_url("test", "https://x.test/path", max_attempts=3)
    assert mock_get.call_count == 3
    assert result.flagged is True


def test_check_rate_limiting_for_url_uses_post_with_json_body():
    with patch("requests.post", return_value=MagicMock(status_code=429)) as mock_post:
        result = check_rate_limiting_for_url(
            "test", "https://x.test/path", method="post", json_body={"a": 1}, max_attempts=2
        )
    assert mock_post.call_args.kwargs["json"] == {"a": 1}
    assert result.flagged is False


def test_check_rate_limiting_for_url_uses_provided_session():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    check_rate_limiting_for_url("test", "https://x.test/path", session=session, max_attempts=2)
    assert session.get.call_count == 2
