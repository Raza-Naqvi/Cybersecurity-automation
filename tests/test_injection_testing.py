from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.injection_testing import (
    InjectionPoint,
    check_nosql_injection,
    check_reflected_xss,
    check_sql_injection,
    run_injection_suite,
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


def test_check_sql_injection_flags_error_signature(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=500, text="You have an error in your SQL syntax near...")
        results = check_sql_injection(target, point)

    assert all(result.flagged for result in results)
    assert len(results) > 0


def test_check_sql_injection_not_flagged_on_clean_response(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, text="<html>no results</html>")
        results = check_sql_injection(target, point)

    assert all(not result.flagged for result in results)


def test_check_sql_injection_uses_post_for_form_points(target):
    point = InjectionPoint(name="contact form", path="/contact", method="post", param_name="message", param_location="form")
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, text="thanks")
        check_sql_injection(target, point)

    assert mock_post.called
    assert mock_post.call_args.kwargs["data"]["message"] in (
        payload for payload in mock_post.call_args.kwargs["data"].values()
    )


def test_check_nosql_injection_skips_non_json_location(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    results = check_nosql_injection(target, point)
    assert len(results) == 1
    assert results[0].flagged is False
    assert "skipped" in results[0].detail.lower()


def test_check_nosql_injection_flags_successful_operator_payload(target):
    point = InjectionPoint(
        name="login", path="/api/login", method="post", param_name="password", param_location="json",
        extra_params={"username": "a"},
    )
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, text='{"token": "abc"}')
        results = check_nosql_injection(target, point)

    assert all(result.flagged for result in results)


def test_check_nosql_injection_not_flagged_on_rejection(target):
    point = InjectionPoint(
        name="login", path="/api/login", method="post", param_name="password", param_location="json",
        extra_params={"username": "a"},
    )
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=400, text='{"error": "invalid password format"}')
        results = check_nosql_injection(target, point)

    assert all(not result.flagged for result in results)


def test_check_reflected_xss_flags_unescaped_reflection(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    captured = {}

    def fake_get(url, params=None, timeout=None):
        captured["payload"] = params["q"]
        return MagicMock(status_code=200, text=f"results for {params['q']}")

    with patch("requests.get", side_effect=fake_get):
        result = check_reflected_xss(target, point)

    assert result.flagged is True
    assert captured["payload"] in result.payload


def test_check_reflected_xss_not_flagged_when_escaped(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    with patch("requests.get", return_value=MagicMock(status_code=200, text="results for &lt;script&gt;")):
        result = check_reflected_xss(target, point)

    assert result.flagged is False


def test_run_injection_suite_combines_all_categories(target):
    point = InjectionPoint(name="search", path="/search", param_name="q", param_location="query")
    with patch("requests.get", return_value=MagicMock(status_code=200, text="clean")):
        results = run_injection_suite(target, point)

    categories = {result.category for result in results}
    assert categories == {"sqli", "nosqli", "xss"}
