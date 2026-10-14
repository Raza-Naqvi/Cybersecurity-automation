"""Phase 4.2/4.4 (security-playbook.md) WordPress-specific black-box
enumeration — our own alternative to WPScan.

WPScan's CLI itself only needs an API token/key for *vulnerability
lookups* (matching a detected version against known CVEs); its
enumeration features (core/plugin/theme/user detection) already work
without one. This module reimplements that enumeration side directly
over plain HTTP(S), so there's no external tool to install, no daily
request cap, and no "non-commercial use only" restriction. Matching
detected versions against a vulnerability database is a separate,
later module — this one only detects what's installed.

Every request goes through `security_toolkit.scope_guard`, same as
every other HTTP-based check in this toolkit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import requests

from security_toolkit.config import Target
from security_toolkit.recon.rate_limit_check import RateLimitResult, check_rate_limiting_for_url
from security_toolkit.scope_guard import resolve_in_scope_url

# A small, well-known set of plugin slugs to probe actively (readme.txt)
# when passive detection (scanning the homepage's own enqueued
# script/link tags) doesn't find enough on its own — the same "known
# wordlist, bounded" idea as dir_enum.py, just WordPress-specific and
# far smaller, since this is a targeted probe, not a general brute-force.
DEFAULT_PLUGIN_SLUGS = (
    "woocommerce", "contact-form-7", "wordpress-seo", "elementor", "jetpack",
    "wordfence", "akismet", "really-simple-ssl", "wp-super-cache",
    "all-in-one-wp-migration", "duplicate-post", "classic-editor",
    "advanced-custom-fields", "wp-mail-smtp", "updraftplus",
    "mailchimp-for-wp", "wp-fastest-cache", "redirection", "wpforms-lite",
    "litespeed-cache", "autoptimize", "really-simple-captcha",
    "w3-total-cache", "google-analytics-for-wordpress", "revslider",
    "ninja-forms", "give", "woocommerce-gateway-stripe", "polylang",
    "wp-rocket",
)

_PLUGIN_PATH_RE = re.compile(r"wp-content/plugins/([a-zA-Z0-9_-]+)")
_THEME_PATH_RE = re.compile(r"wp-content/themes/([a-zA-Z0-9_-]+)")
_PLUGIN_README_VERSION_RE = re.compile(r"Stable tag:\s*([0-9][0-9.]*)", re.IGNORECASE)
_THEME_STYLE_VERSION_RE = re.compile(r"Version:\s*([0-9][0-9.]*)", re.IGNORECASE)
_CORE_README_VERSION_RE = re.compile(r"Version\s+([0-9][0-9.]*)", re.IGNORECASE)
_GENERATOR_META_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9][0-9.]*)', re.IGNORECASE
)
_AUTHOR_SLUG_RE = re.compile(r"/author/([^/]+)/?")

DEFAULT_USER_MAX_ID = 10


@dataclass(frozen=True)
class SoftwareFinding:
    slug: str
    version: str | None
    source: str  # "passive" (seen in homepage markup) or "active" (probed directly)


@dataclass(frozen=True)
class WpEnumResult:
    is_wordpress: bool
    core_version: str | None
    plugins: tuple[SoftwareFinding, ...]
    themes: tuple[SoftwareFinding, ...]
    usernames: tuple[str, ...]
    rate_limit: RateLimitResult | None
    detail: str


def detect_wordpress(target: Target, timeout: float = 10.0) -> bool:
    """Cheap signal: does the homepage reference wp-content/wp-includes,
    or does wp-json respond with the expected shape? Either one alone
    is enough — this gates every other check in this module, so a
    false negative here means a real check gets skipped.
    """
    url = resolve_in_scope_url(target, "/")
    response = requests.get(url, timeout=timeout)
    if "wp-content" in response.text or "wp-includes" in response.text:
        return True

    wp_json_url = resolve_in_scope_url(target, "/wp-json/")
    wp_json_response = requests.get(wp_json_url, timeout=timeout)
    return wp_json_response.status_code == 200 and "namespaces" in wp_json_response.text


def check_core_version(target: Target, timeout: float = 10.0) -> str | None:
    """Try readme.html first (the file every WordPress release ships
    with), then fall back to the homepage's <meta name="generator"> tag.
    """
    readme_url = resolve_in_scope_url(target, "/readme.html")
    readme_response = requests.get(readme_url, timeout=timeout)
    if readme_response.status_code == 200:
        match = _CORE_README_VERSION_RE.search(readme_response.text)
        if match:
            return match.group(1)

    homepage_url = resolve_in_scope_url(target, "/")
    homepage_response = requests.get(homepage_url, timeout=timeout)
    match = _GENERATOR_META_RE.search(homepage_response.text)
    return match.group(1) if match else None


def _passive_slugs(html: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(pattern.findall(html)))  # de-dupe, keep first-seen order


def enumerate_plugins_passive(target: Target, timeout: float = 10.0) -> tuple[SoftwareFinding, ...]:
    """Scan the homepage's own markup for wp-content/plugins/<slug> refs
    (enqueued <script>/<link> tags) — zero extra requests beyond the
    one page fetch, and it only ever reports what's actually loaded.
    """
    url = resolve_in_scope_url(target, "/")
    response = requests.get(url, timeout=timeout)
    slugs = _passive_slugs(response.text, _PLUGIN_PATH_RE)
    return tuple(SoftwareFinding(slug=slug, version=None, source="passive") for slug in slugs)


def enumerate_plugins_active(
    target: Target, slugs: tuple[str, ...] = DEFAULT_PLUGIN_SLUGS, timeout: float = 10.0
) -> tuple[SoftwareFinding, ...]:
    """Probe each candidate slug's readme.txt directly — the only way to
    find an installed-but-not-currently-enqueued plugin. A timeout or
    connection error on one slug is skipped, not fatal to the sweep.
    """
    found = []
    for slug in slugs:
        url = resolve_in_scope_url(target, f"/wp-content/plugins/{slug}/readme.txt")
        try:
            response = requests.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if response.status_code != 200:
            continue
        match = _PLUGIN_README_VERSION_RE.search(response.text)
        found.append(SoftwareFinding(slug=slug, version=match.group(1) if match else None, source="active"))
    return tuple(found)


def enumerate_themes(target: Target, timeout: float = 10.0) -> tuple[SoftwareFinding, ...]:
    """Passive: find the active theme's slug from the homepage's own
    markup, then actively fetch its style.css for the version header.
    Themes are singular (one active theme), unlike plugins, so no
    wordlist brute-force is needed here.
    """
    url = resolve_in_scope_url(target, "/")
    response = requests.get(url, timeout=timeout)
    slugs = _passive_slugs(response.text, _THEME_PATH_RE)

    found = []
    for slug in slugs:
        style_url = resolve_in_scope_url(target, f"/wp-content/themes/{slug}/style.css")
        try:
            style_response = requests.get(style_url, timeout=timeout)
        except requests.RequestException:
            found.append(SoftwareFinding(slug=slug, version=None, source="passive"))
            continue
        if style_response.status_code != 200:
            found.append(SoftwareFinding(slug=slug, version=None, source="passive"))
            continue
        match = _THEME_STYLE_VERSION_RE.search(style_response.text)
        found.append(SoftwareFinding(slug=slug, version=match.group(1) if match else None, source="active"))
    return tuple(found)


def enumerate_users(target: Target, max_id: int = DEFAULT_USER_MAX_ID, timeout: float = 10.0) -> tuple[str, ...]:
    """Try the REST API first (often open by default, returns real
    usernames/slugs directly); fall back to the classic
    ?author=N -> redirect-to-/author/<name>/ trick, bounded the same
    way idor_tester.check_sequential_id_enumeration bounds its range.
    """
    rest_url = resolve_in_scope_url(target, "/wp-json/wp/v2/users")
    rest_response = requests.get(rest_url, timeout=timeout)
    if rest_response.status_code == 200:
        try:
            data = rest_response.json()
        except ValueError:
            data = []
        usernames = tuple(dict.fromkeys(entry.get("slug", "") for entry in data if entry.get("slug")))
        if usernames:
            return usernames

    found = []
    for user_id in range(1, max_id + 1):
        author_url = resolve_in_scope_url(target, f"/?author={user_id}")
        try:
            response = requests.get(author_url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if response.status_code not in (301, 302):
            continue
        match = _AUTHOR_SLUG_RE.search(response.headers.get("Location", ""))
        if match:
            found.append(match.group(1))
    return tuple(dict.fromkeys(found))


def run_wp_enum(
    target: Target,
    plugin_slugs: tuple[str, ...] = DEFAULT_PLUGIN_SLUGS,
    user_max_id: int = DEFAULT_USER_MAX_ID,
    check_rate_limit: bool = True,
    timeout: float = 10.0,
) -> WpEnumResult:
    """Orchestrates the whole black-box WordPress sweep. Gated by
    `detect_wordpress` — a non-WordPress target gets that one cheap
    check and nothing else, same "no wasted requests" discipline as
    the rest of this toolkit.
    """
    if not detect_wordpress(target, timeout=timeout):
        return WpEnumResult(
            is_wordpress=False,
            core_version=None,
            plugins=(),
            themes=(),
            usernames=(),
            rate_limit=None,
            detail="Target does not look like WordPress — nothing further checked.",
        )

    core_version = check_core_version(target, timeout=timeout)

    passive_plugins = enumerate_plugins_passive(target, timeout=timeout)
    passive_slugs = tuple(finding.slug for finding in passive_plugins)
    # Actively probe every passively-found slug too (its readme.txt is the
    # only way to get a version for it — a passive hit alone never reveals
    # one), plus whatever's left of the wordlist, to find plugins that
    # aren't currently enqueued on the homepage at all.
    wordlist_slugs = tuple(slug for slug in plugin_slugs if slug not in passive_slugs)
    active_plugins = enumerate_plugins_active(target, slugs=passive_slugs + wordlist_slugs, timeout=timeout)
    active_by_slug = {finding.slug: finding for finding in active_plugins}
    plugins = tuple(active_by_slug.get(finding.slug, finding) for finding in passive_plugins) + tuple(
        finding for finding in active_plugins if finding.slug not in passive_slugs
    )

    themes = enumerate_themes(target, timeout=timeout)
    usernames = enumerate_users(target, max_id=user_max_id, timeout=timeout)

    rate_limit = None
    if check_rate_limit:
        rest_url = resolve_in_scope_url(target, "/wp-json/wp/v2/users")
        rate_limit = check_rate_limiting_for_url("WordPress user enumeration (rate limit)", rest_url)

    detail = (
        f"core version: {core_version or 'unknown'}; "
        f"{len(plugins)} plugin(s) detected; {len(themes)} theme(s) detected; "
        f"{len(usernames)} username(s) enumerated."
    )
    return WpEnumResult(
        is_wordpress=True,
        core_version=core_version,
        plugins=plugins,
        themes=themes,
        usernames=usernames,
        rate_limit=rate_limit,
        detail=detail,
    )
