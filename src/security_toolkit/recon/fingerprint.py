"""Phase 4.2 (security-playbook.md) reconnaissance — black-box only.

Everything here is a plain HTTP(S) request against the live app, the way
an external tester (or attacker) would see it: no filesystem, no DB, no
server shell, no source code. This maps the attack surface before any of
the other black-box modules (auth testing, IDOR, injection) run.

Every request goes through `security_toolkit.scope_guard`, so nothing
here can touch a URL outside the authorized target's `base_url`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import requests

from security_toolkit.config import Target
from security_toolkit.scope_guard import resolve_in_scope_url

# Paths that should never be reachable on a properly configured site.
# A 200 here is a strong signal, not a mutation — this only ever GETs.
SENSITIVE_PATHS = (
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.example",
    "/wp-config.php.bak",
    "/wp-config.php.save",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/.DS_Store",
    "/composer.json",
    "/package.json",
    "/.well-known/security.txt",
)

TECH_HEADER_NAMES = ("Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache", "X-AspNet-Version")

# Cookie-name -> framework hints, for a quick guess without fetching anything extra.
COOKIE_TECH_HINTS = {
    "wordpress_logged_in": "WordPress",
    "wp-settings": "WordPress",
    "laravel_session": "Laravel",
    "xsrf-token": "Laravel (or another framework using the same convention)",
    "phpsessid": "PHP",
    "connect.sid": "Node/Express (connect/express-session)",
    "jsessionid": "Java (Servlet container)",
}


@dataclass(frozen=True)
class ExposedFileResult:
    path: str
    url: str
    status_code: int
    flagged: bool
    detail: str


@dataclass(frozen=True)
class HeaderFingerprint:
    tech_headers: dict  # header name -> value, only for headers actually present
    cookie_hints: tuple[str, ...]  # framework guesses from cookie names seen
    missing_security_headers: tuple[str, ...]


@dataclass(frozen=True)
class XmlRpcResult:
    enabled: bool
    risky_methods_exposed: tuple[str, ...]
    detail: str


SECURITY_HEADERS_TO_CHECK = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
)

# Methods the playbook calls out by name as brute-force/enumeration risks
# when exposed on xmlrpc.php (Phase 2, item 2).
RISKY_XMLRPC_METHODS = ("wp.getUsersBlogs", "system.multicall")


def check_exposed_files(target: Target, paths: tuple[str, ...] = SENSITIVE_PATHS, timeout: float = 10.0) -> tuple[ExposedFileResult, ...]:
    """GET a list of paths that should never be publicly reachable.

    A 200 is flagged; a redirect to a generic error/home page is not (many
    sites return 200 for a custom 404 page, so this also treats an
    unusually short or templated-looking body as non-flagged — still,
    always eyeball a flagged result before reporting it as confirmed).
    """
    results = []
    for path in paths:
        url = resolve_in_scope_url(target, path)
        response = requests.get(url, timeout=timeout, allow_redirects=False)
        flagged = response.status_code == 200
        results.append(
            ExposedFileResult(
                path=path,
                url=url,
                status_code=response.status_code,
                flagged=flagged,
                detail=(
                    f"status {response.status_code} — reachable, review the response body"
                    if flagged
                    else f"status {response.status_code}"
                ),
            )
        )
    return tuple(results)


def fingerprint_headers(target: Target, timeout: float = 10.0) -> HeaderFingerprint:
    """Fetch the homepage once and read tech-revealing headers + cookies."""
    url = resolve_in_scope_url(target, "/")
    response = requests.get(url, timeout=timeout)

    tech_headers = {name: response.headers[name] for name in TECH_HEADER_NAMES if name in response.headers}

    cookie_hints = tuple(
        sorted(
            {
                hint
                for cookie_name in response.cookies.keys()
                for key, hint in COOKIE_TECH_HINTS.items()
                if key in cookie_name.lower()
            }
        )
    )

    missing = tuple(name for name in SECURITY_HEADERS_TO_CHECK if name not in response.headers)

    return HeaderFingerprint(tech_headers=tech_headers, cookie_hints=cookie_hints, missing_security_headers=missing)


def check_xmlrpc(target: Target, timeout: float = 10.0) -> XmlRpcResult:
    """Phase 2 item 2 of the playbook, used here as a recon signal: is
    xmlrpc.php present, and does it expose the two methods called out as a
    brute-force/enumeration risk?
    """
    url = resolve_in_scope_url(target, "/xmlrpc.php")
    list_methods_body = (
        '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    )
    response = requests.post(url, data=list_methods_body, timeout=timeout)

    if response.status_code != 200 or "<methodResponse>" not in response.text:
        return XmlRpcResult(enabled=False, risky_methods_exposed=(), detail=f"not reachable (status {response.status_code})")

    exposed = tuple(method for method in RISKY_XMLRPC_METHODS if method in response.text)
    detail = (
        f"xmlrpc.php is reachable and exposes: {', '.join(exposed)}"
        if exposed
        else "xmlrpc.php is reachable but the risky methods weren't listed"
    )
    return XmlRpcResult(enabled=True, risky_methods_exposed=exposed, detail=detail)


def check_robots_and_sitemap(target: Target, timeout: float = 10.0) -> dict:
    """Fetch robots.txt and sitemap.xml, return their raw content (empty
    string if missing) plus any Disallow paths — unlinked/hidden paths
    worth investigating further.
    """
    robots_url = resolve_in_scope_url(target, "/robots.txt")
    robots_response = requests.get(robots_url, timeout=timeout)
    robots_text = robots_response.text if robots_response.status_code == 200 else ""
    disallowed = tuple(
        match.group(1).strip()
        for match in re.finditer(r"^Disallow:\s*(\S+)", robots_text, re.IGNORECASE | re.MULTILINE)
    )

    sitemap_url = resolve_in_scope_url(target, "/sitemap.xml")
    sitemap_response = requests.get(sitemap_url, timeout=timeout)
    sitemap_present = sitemap_response.status_code == 200

    return {
        "robots_txt": robots_text,
        "disallowed_paths": disallowed,
        "sitemap_present": sitemap_present,
    }
