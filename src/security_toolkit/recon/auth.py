"""Pluggable login adapters so the IDOR tester works across different
sites without new code per site — WordPress, Laravel, and a custom
Node/Express app all authenticate differently, so each one is a small,
data-driven adapter selected by the `auth.type` field in config/scope.json,
not a hardcoded flow.

Every adapter's contract is the same: given a `requests.Session` and
`Credentials`, log in and mutate the session (set a cookie or an auth
header) so later requests on that session are authenticated as that user.
None of these ever log the password; failures report the HTTP status only.

Supported `auth.type` values and their scope.json shape:

    "wordpress" (cookie-based, wp-login.php):
        {"type": "wordpress", "login_url": "https://site/wp-login.php"}

    "form_session" (classic server-rendered login, optional CSRF token —
    covers most Laravel apps and similar frameworks):
        {
          "type": "form_session",
          "login_url": "https://site/login",
          "username_field": "email", "password_field": "password",
          "csrf": {"page_url": "https://site/login", "field_name": "_token"}
        }

    "json_token" (JSON API login returning a bearer token — covers most
    custom Node/Express APIs):
        {
          "type": "json_token",
          "login_url": "https://site/api/login",
          "username_field": "email", "password_field": "password",
          "token_path": "data.token",
          "header_name": "Authorization", "header_prefix": "Bearer "
        }

A site that doesn't fit any of these (custom MFA, SSO, etc.) can still use
this tool — write a one-off adapter that implements the same `login`
method and pass it directly to `run_idor_suite` instead of going through
`build_auth_provider`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

import requests

from security_toolkit.config import Credentials
from security_toolkit.json_paths import lookup_dotted_path


class AuthConfigError(ValueError):
    """Raised when an `auth` block in scope.json is missing required keys."""


class AuthFailure(RuntimeError):
    """Raised when a login attempt doesn't succeed."""


@dataclass(frozen=True)
class AuthResult:
    logged_in: bool
    status_code: int
    detail: str
    token: str | None = None  # the extracted bearer token, for json_token logins
    set_cookie_headers: tuple[str, ...] = ()  # raw Set-Cookie header values from the login response


class AuthProvider(Protocol):
    def login(self, session: requests.Session, credentials: Credentials) -> AuthResult: ...


def _require(config: dict, key: str, auth_type: str) -> Any:
    if key not in config:
        raise AuthConfigError(f"auth.type={auth_type!r} requires '{key}' in scope.json")
    return config[key]


def _lookup_path(data: dict, dotted_path: str) -> Any:
    found = lookup_dotted_path(data, dotted_path)
    if found is None:
        raise AuthFailure(f"Login response had no field at path '{dotted_path}'")
    return found


def _extract_csrf_token(html: str, field_name: str) -> str:
    """Pull a hidden input's value out of an HTML login form.

    Tries both attribute orders (name-before-value and value-before-name)
    since different templating engines emit them differently.
    """
    patterns = (
        rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']',
        rf'value=["\']([^"\']+)["\'][^>]*name=["\']{re.escape(field_name)}["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    raise AuthFailure(f"Could not find a '{field_name}' hidden field on the login page")


@dataclass(frozen=True)
class FormSessionAuthProvider:
    """Classic server-rendered login: POST a form, server sets a session
    cookie. Covers WordPress (as a thin wrapper, see `wordpress_auth_provider`
    below) and most Laravel/PHP apps that use a CSRF-protected web login.
    """

    login_url: str
    username_field: str = "username"
    password_field: str = "password"
    csrf_page_url: str | None = None
    csrf_field_name: str | None = None
    extra_fields: dict[str, str] | None = None
    success_check: Any = None  # optional callable(requests.Response) -> bool
    timeout: float = 10.0

    def login(self, session: requests.Session, credentials: Credentials) -> AuthResult:
        payload = {
            self.username_field: credentials.username,
            self.password_field: credentials.password,
            **(self.extra_fields or {}),
        }
        if self.csrf_page_url and self.csrf_field_name:
            page = session.get(self.csrf_page_url, timeout=self.timeout)
            payload[self.csrf_field_name] = _extract_csrf_token(page.text, self.csrf_field_name)

        response = session.post(self.login_url, data=payload, timeout=self.timeout, allow_redirects=True)
        succeeded = (
            self.success_check(response)
            if self.success_check is not None
            else (response.status_code < 400 and len(session.cookies) > 0)
        )
        return AuthResult(
            logged_in=succeeded,
            status_code=response.status_code,
            detail="login OK" if succeeded else f"login failed (status {response.status_code})",
            set_cookie_headers=tuple(response.raw.headers.getlist("Set-Cookie")) if response.raw else (),
        )


@dataclass(frozen=True)
class JsonTokenAuthProvider:
    """JSON API login: POST credentials, read a bearer token out of the
    response body, attach it to the session as a header. Covers most
    custom Node/Express (and similar) token-based APIs.
    """

    login_url: str
    username_field: str = "username"
    password_field: str = "password"
    token_path: str = "token"
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "
    timeout: float = 10.0

    def login(self, session: requests.Session, credentials: Credentials) -> AuthResult:
        payload = {self.username_field: credentials.username, self.password_field: credentials.password}
        response = session.post(self.login_url, json=payload, timeout=self.timeout)
        if response.status_code >= 400:
            return AuthResult(
                logged_in=False, status_code=response.status_code, detail=f"login failed (status {response.status_code})"
            )
        try:
            body = response.json()
            token = _lookup_path(body, self.token_path)
        except (ValueError, AuthFailure) as exc:
            return AuthResult(logged_in=False, status_code=response.status_code, detail=str(exc))
        session.headers[self.header_name] = f"{self.header_prefix}{token}"
        return AuthResult(
            logged_in=True,
            status_code=response.status_code,
            detail="login OK",
            token=str(token),
            set_cookie_headers=tuple(response.raw.headers.getlist("Set-Cookie")) if response.raw else (),
        )


def wordpress_auth_provider(login_url: str) -> FormSessionAuthProvider:
    """WordPress's wp-login.php: fields are named 'log'/'pwd', no CSRF
    token on the default login form.
    """
    return FormSessionAuthProvider(login_url=login_url, username_field="log", password_field="pwd")


def build_auth_provider(auth_config: dict) -> AuthProvider:
    """Build the right adapter from a target's `auth` block in scope.json."""
    auth_type = auth_config.get("type")
    if auth_type == "wordpress":
        return wordpress_auth_provider(_require(auth_config, "login_url", auth_type))

    if auth_type == "form_session":
        csrf = auth_config.get("csrf") or {}
        return FormSessionAuthProvider(
            login_url=_require(auth_config, "login_url", auth_type),
            username_field=auth_config.get("username_field", "username"),
            password_field=auth_config.get("password_field", "password"),
            csrf_page_url=csrf.get("page_url"),
            csrf_field_name=csrf.get("field_name"),
            extra_fields=auth_config.get("extra_fields"),
        )

    if auth_type == "json_token":
        return JsonTokenAuthProvider(
            login_url=_require(auth_config, "login_url", auth_type),
            username_field=auth_config.get("username_field", "username"),
            password_field=auth_config.get("password_field", "password"),
            token_path=auth_config.get("token_path", "token"),
            header_name=auth_config.get("header_name", "Authorization"),
            header_prefix=auth_config.get("header_prefix", "Bearer "),
        )

    raise AuthConfigError(
        f"Unknown auth.type '{auth_type}'. Supported: wordpress, form_session, json_token "
        "— or write a one-off adapter with a login(session, credentials) method and skip this factory."
    )


def login(provider: AuthProvider, credentials: Credentials) -> tuple[requests.Session, AuthResult]:
    """Create a fresh session and log it in. Raises AuthFailure if it didn't work."""
    session = requests.Session()
    result = provider.login(session, credentials)
    if not result.logged_in:
        raise AuthFailure(result.detail)
    return session, result
