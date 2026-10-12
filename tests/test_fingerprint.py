from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.fingerprint import (
    check_exposed_files,
    check_robots_and_sitemap,
    check_xmlrpc,
    fingerprint_headers,
)
from security_toolkit.scope_guard import OutOfScopeError


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


def test_check_exposed_files_flags_200(target):
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        results = check_exposed_files(target, paths=("/.env",))
    assert results[0].flagged is True


def test_check_exposed_files_does_not_flag_404(target):
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=404)
        results = check_exposed_files(target, paths=("/.env",))
    assert results[0].flagged is False


def test_check_exposed_files_stays_in_scope(target):
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        check_exposed_files(target, paths=("/.env",))
        called_url = mock_get.call_args.args[0]
    assert called_url.startswith(target.base_url)


def test_fingerprint_headers_detects_wordpress_cookie(target):
    response = MagicMock(status_code=200, headers={"Server": "nginx"})
    response.cookies.keys.return_value = ["wordpress_logged_in_abc123"]
    with patch("requests.get", return_value=response):
        result = fingerprint_headers(target)
    assert "WordPress" in result.cookie_hints
    assert result.tech_headers == {"Server": "nginx"}


def test_fingerprint_headers_reports_missing_security_headers(target):
    response = MagicMock(status_code=200, headers={})
    response.cookies.keys.return_value = []
    with patch("requests.get", return_value=response):
        result = fingerprint_headers(target)
    assert "Content-Security-Policy" in result.missing_security_headers


def test_check_xmlrpc_flags_risky_methods_exposed(target):
    response = MagicMock(
        status_code=200,
        text="<methodResponse><value>wp.getUsersBlogs system.multicall</value></methodResponse>",
    )
    with patch("requests.post", return_value=response):
        result = check_xmlrpc(target)
    assert result.enabled is True
    assert "wp.getUsersBlogs" in result.risky_methods_exposed


def test_check_xmlrpc_not_enabled_on_404(target):
    with patch("requests.post", return_value=MagicMock(status_code=404, text="")):
        result = check_xmlrpc(target)
    assert result.enabled is False
    assert result.risky_methods_exposed == ()


def test_check_robots_and_sitemap_parses_disallow_lines(target):
    robots_response = MagicMock(status_code=200, text="User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n")
    sitemap_response = MagicMock(status_code=200)
    with patch("requests.get", side_effect=[robots_response, sitemap_response]):
        result = check_robots_and_sitemap(target)
    assert result["disallowed_paths"] == ("/admin", "/wp-admin")
    assert result["sitemap_present"] is True


def test_check_robots_and_sitemap_handles_missing_files(target):
    missing = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[missing, missing]):
        result = check_robots_and_sitemap(target)
    assert result["robots_txt"] == ""
    assert result["sitemap_present"] is False


def test_fingerprint_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(OutOfScopeError):
        check_exposed_files(target_no_url, paths=("/.env",))
