from unittest.mock import MagicMock, patch

import pytest
import requests as requests_module

from security_toolkit.config import Target
from security_toolkit.recon.rate_limit_check import RateLimitResult
from security_toolkit.recon.wp_enum import (
    SoftwareFinding,
    check_core_version,
    detect_wordpress,
    enumerate_plugins_active,
    enumerate_plugins_passive,
    enumerate_themes,
    enumerate_users,
    run_wp_enum,
)
from security_toolkit.scope_guard import OutOfScopeError


@pytest.fixture
def target():
    return Target(
        name="staging",
        type="wordpress",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com",
        known_admin_logins=(),
        notes="",
        auth=None,
    )


def test_detect_wordpress_true_from_markup(target):
    with patch("requests.get", return_value=MagicMock(status_code=200, text="<script src='/wp-content/themes/x/style.css'>")):
        assert detect_wordpress(target) is True


def test_detect_wordpress_false_when_no_signal(target):
    home = MagicMock(status_code=200, text="<html>plain site</html>")
    wp_json = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[home, wp_json]) as mock_get:
        assert detect_wordpress(target) is False
    assert mock_get.call_count == 2


def test_detect_wordpress_true_via_wp_json(target):
    home = MagicMock(status_code=200, text="<html>plain</html>")
    wp_json = MagicMock(status_code=200, text='{"namespaces": ["wp/v2"]}')
    with patch("requests.get", side_effect=[home, wp_json]):
        assert detect_wordpress(target) is True


def test_check_core_version_from_readme(target):
    readme = MagicMock(status_code=200, text="Version 6.4.2\nmore text")
    with patch("requests.get", return_value=readme):
        assert check_core_version(target) == "6.4.2"


def test_check_core_version_from_generator_meta_when_readme_missing(target):
    readme = MagicMock(status_code=404, text="")
    homepage = MagicMock(status_code=200, text='<meta name="generator" content="WordPress 6.3.1">')
    with patch("requests.get", side_effect=[readme, homepage]):
        assert check_core_version(target) == "6.3.1"


def test_check_core_version_none_when_neither_present(target):
    readme = MagicMock(status_code=404, text="")
    homepage = MagicMock(status_code=200, text="<html>no hint</html>")
    with patch("requests.get", side_effect=[readme, homepage]):
        assert check_core_version(target) is None


def test_enumerate_plugins_passive_dedupes(target):
    html = (
        "<script src='/wp-content/plugins/woocommerce/js/a.js'></script>"
        "<script src='/wp-content/plugins/woocommerce/js/b.js'></script>"
        "<link href='/wp-content/plugins/elementor/css/x.css'>"
    )
    with patch("requests.get", return_value=MagicMock(status_code=200, text=html)):
        findings = enumerate_plugins_passive(target)
    assert [f.slug for f in findings] == ["woocommerce", "elementor"]
    assert all(f.source == "passive" for f in findings)


def test_enumerate_plugins_passive_extracts_version_from_ver_query_string(target):
    """WordPress enqueues assets with a ?ver= cache-busting query string
    matching the plugin's own version — a real version, zero extra
    requests, and it still works when readme.txt is blocked.
    """
    html = "<script src='/wp-content/plugins/cookie-law-info/public/js/cli.js?ver=2.19.1'></script>"
    with patch("requests.get", return_value=MagicMock(status_code=200, text=html)):
        findings = enumerate_plugins_passive(target)
    assert findings == (SoftwareFinding(slug="cookie-law-info", version="2.19.1", source="passive"),)


def test_enumerate_plugins_active_finds_version_and_skips_missing(target):
    found = MagicMock(status_code=200, text="Stable tag: 8.1.0\n")
    missing = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[found, missing]):
        findings = enumerate_plugins_active(target, slugs=("woocommerce", "nope"))
    assert findings == (SoftwareFinding(slug="woocommerce", version="8.1.0", source="active"),)


def test_enumerate_plugins_active_survives_request_exception(target):
    found = MagicMock(status_code=200, text="Stable tag: 1.0.0\n")
    with patch("requests.get", side_effect=[requests_module.exceptions.ConnectionError(), found]):
        findings = enumerate_plugins_active(target, slugs=("broken", "ok"))
    assert findings == (SoftwareFinding(slug="ok", version="1.0.0", source="active"),)


def test_enumerate_themes_parses_version(target):
    homepage = MagicMock(status_code=200, text="<link href='/wp-content/themes/twentytwentyfour/style.css'>")
    style = MagicMock(status_code=200, text="Theme Name: Twenty Twenty-Four\nVersion: 1.2\n")
    with patch("requests.get", side_effect=[homepage, style]):
        findings = enumerate_themes(target)
    assert findings == (SoftwareFinding(slug="twentytwentyfour", version="1.2", source="active"),)


def test_enumerate_themes_extracts_version_from_ver_query_string_without_active_fetch(target):
    html = "<link href='/wp-content/themes/atumlabs/style.css?ver=4.2.0'>"
    with patch("requests.get", return_value=MagicMock(status_code=200, text=html)) as mock_get:
        findings = enumerate_themes(target)
    assert findings == (SoftwareFinding(slug="atumlabs", version="4.2.0", source="passive"),)
    mock_get.assert_called_once()  # no active style.css fetch needed — the version is already known


def test_enumerate_themes_handles_missing_style_css(target):
    homepage = MagicMock(status_code=200, text="<link href='/wp-content/themes/custom/style.css'>")
    style = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[homepage, style]):
        findings = enumerate_themes(target)
    assert findings == (SoftwareFinding(slug="custom", version=None, source="passive"),)


def test_enumerate_themes_survives_request_exception(target):
    homepage = MagicMock(status_code=200, text="<link href='/wp-content/themes/custom/style.css'>")
    with patch("requests.get", side_effect=[homepage, requests_module.exceptions.ConnectionError()]):
        findings = enumerate_themes(target)
    assert findings == (SoftwareFinding(slug="custom", version=None, source="passive"),)


def test_enumerate_users_via_rest_api(target):
    rest = MagicMock(status_code=200)
    rest.json.return_value = [{"slug": "admin"}, {"slug": "editor"}]
    with patch("requests.get", return_value=rest):
        usernames = enumerate_users(target)
    assert usernames == ("admin", "editor")


def test_enumerate_users_falls_back_when_rest_empty(target):
    rest = MagicMock(status_code=200)
    rest.json.return_value = []
    author1 = MagicMock(status_code=301, headers={"Location": "https://staging.example.com/author/admin/"})
    author2 = MagicMock(status_code=404, headers={})
    with patch("requests.get", side_effect=[rest, author1, author2]):
        usernames = enumerate_users(target, max_id=2)
    assert usernames == ("admin",)


def test_enumerate_users_falls_back_when_rest_disabled(target):
    rest = MagicMock(status_code=404)
    author1 = MagicMock(status_code=302, headers={"Location": "https://staging.example.com/author/bob/"})
    with patch("requests.get", side_effect=[rest, author1]):
        usernames = enumerate_users(target, max_id=1)
    assert usernames == ("bob",)


def test_enumerate_users_bounded_by_max_id(target):
    rest = MagicMock(status_code=404)
    no_redirect = MagicMock(status_code=404, headers={})
    with patch("requests.get", side_effect=[rest] + [no_redirect] * 5) as mock_get:
        usernames = enumerate_users(target, max_id=5)
    assert usernames == ()
    assert mock_get.call_count == 6


def test_enumerate_users_survives_request_exception(target):
    rest = MagicMock(status_code=404)
    with patch("requests.get", side_effect=[rest, requests_module.exceptions.ConnectionError()]):
        usernames = enumerate_users(target, max_id=1)
    assert usernames == ()


def test_run_wp_enum_short_circuits_on_non_wordpress(target):
    home = MagicMock(status_code=200, text="<html>plain</html>")
    wp_json = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[home, wp_json]) as mock_get:
        result = run_wp_enum(target, check_rate_limit=False)
    assert result.is_wordpress is False
    assert mock_get.call_count == 2
    assert result.plugins == ()
    assert result.themes == ()
    assert result.usernames == ()


def test_run_wp_enum_skips_active_probe_when_passive_version_known(target):
    home_detect = MagicMock(status_code=200, text="<html>wp-content here</html>")
    readme_core = MagicMock(status_code=200, text="Version 6.4.2\n")
    homepage_plugins = MagicMock(
        status_code=200, text="<script src='/wp-content/plugins/cookie-law-info/cli.js?ver=2.19.1'>"
    )
    homepage_themes = MagicMock(status_code=200, text="<html>no theme refs</html>")
    rest_users = MagicMock(status_code=401)

    with patch(
        "requests.get",
        side_effect=[home_detect, readme_core, homepage_plugins, homepage_themes, rest_users],
    ) as mock_get:
        result = run_wp_enum(target, plugin_slugs=(), user_max_id=0, check_rate_limit=False)

    assert result.plugins == (SoftwareFinding(slug="cookie-law-info", version="2.19.1", source="passive"),)
    assert mock_get.call_count == 5  # no readme.txt probe — the version was already known


def test_run_wp_enum_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="wordpress", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(OutOfScopeError):
        run_wp_enum(target_no_url, check_rate_limit=False)


def test_run_wp_enum_happy_path_detects_everything(target):
    home_detect = MagicMock(status_code=200, text="<html>wp-content here</html>")
    readme_core = MagicMock(status_code=200, text="Version 6.4.2\n")
    homepage_plugins = MagicMock(status_code=200, text="<script src='/wp-content/plugins/woocommerce/a.js'>")
    homepage_themes = MagicMock(status_code=200, text="<link href='/wp-content/themes/mytheme/style.css'>")
    style_css = MagicMock(status_code=200, text="Version: 2.0\n")
    rest_users = MagicMock(status_code=200)
    rest_users.json.return_value = [{"slug": "admin"}]

    plugin_readme = MagicMock(status_code=200, text="Stable tag: 8.5.0\n")

    with patch(
        "requests.get",
        side_effect=[home_detect, readme_core, homepage_plugins, plugin_readme, homepage_themes, style_css, rest_users],
    ):
        result = run_wp_enum(target, plugin_slugs=(), user_max_id=0, check_rate_limit=False)

    assert result.is_wordpress is True
    assert result.core_version == "6.4.2"
    # a plugin found passively still gets an active readme.txt probe for its version
    assert result.plugins == (SoftwareFinding(slug="woocommerce", version="8.5.0", source="active"),)
    assert result.themes == (SoftwareFinding(slug="mytheme", version="2.0", source="active"),)
    assert result.usernames == ("admin",)
    assert result.rate_limit is None


def test_run_wp_enum_keeps_passive_finding_when_active_probe_fails(target):
    """If the slug's own readme.txt 404s (e.g. blocked), fall back to the
    passive finding rather than losing the detection entirely.
    """
    home_detect = MagicMock(status_code=200, text="<html>wp-content here</html>")
    readme_core = MagicMock(status_code=404, text="")
    homepage_core_fallback = MagicMock(status_code=200, text="<html>no generator meta</html>")
    homepage_plugins = MagicMock(status_code=200, text="<script src='/wp-content/plugins/cookie-law-info/a.js'>")
    plugin_readme_404 = MagicMock(status_code=404, text="")
    homepage_themes = MagicMock(status_code=200, text="<html>no theme refs</html>")
    rest_users = MagicMock(status_code=401)

    with patch(
        "requests.get",
        side_effect=[
            home_detect, readme_core, homepage_core_fallback, homepage_plugins, plugin_readme_404,
            homepage_themes, rest_users,
        ],
    ):
        result = run_wp_enum(target, plugin_slugs=(), user_max_id=0, check_rate_limit=False)

    assert result.plugins == (SoftwareFinding(slug="cookie-law-info", version=None, source="passive"),)


def test_run_wp_enum_skips_rate_limit_check_for_non_wordpress(target):
    home = MagicMock(status_code=200, text="<html>plain</html>")
    wp_json = MagicMock(status_code=404, text="")
    with patch("requests.get", side_effect=[home, wp_json]), patch(
        "security_toolkit.recon.wp_enum.check_rate_limiting_for_url"
    ) as mock_rl:
        result = run_wp_enum(target, check_rate_limit=True)
    mock_rl.assert_not_called()
    assert result.rate_limit is None


def test_run_wp_enum_calls_rate_limit_when_wordpress_detected(target):
    rate_limit_result = RateLimitResult(
        label="x", attempts=10, status_codes=(200,) * 10, blocked=False, flagged=True, detail="d"
    )
    with patch("security_toolkit.recon.wp_enum.detect_wordpress", return_value=True), patch(
        "security_toolkit.recon.wp_enum.check_core_version", return_value="6.0"
    ), patch("security_toolkit.recon.wp_enum.enumerate_plugins_passive", return_value=()), patch(
        "security_toolkit.recon.wp_enum.enumerate_plugins_active", return_value=()
    ), patch("security_toolkit.recon.wp_enum.enumerate_themes", return_value=()), patch(
        "security_toolkit.recon.wp_enum.enumerate_users", return_value=()
    ), patch(
        "security_toolkit.recon.wp_enum.check_rate_limiting_for_url", return_value=rate_limit_result
    ) as mock_rl:
        result = run_wp_enum(target, check_rate_limit=True)
    mock_rl.assert_called_once()
    assert result.rate_limit is rate_limit_result
