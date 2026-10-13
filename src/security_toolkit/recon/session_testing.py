"""Phase 4.3 (security-playbook.md) authentication & session testing —
black-box only, built on the same `AuthProvider` adapters as the IDOR
tester so it works across WordPress/Laravel/Node without new code per
site.

Covers:
  - session fixation: does the session identifier change after login?
  - logout invalidation: does the session/token actually stop working
    after logout, or just get discarded client-side?
  - login rate-limiting / lockout: does repeated failed login get
    throttled, or can it be retried indefinitely?

Deliberately not covered here (see playbook Phase 4.3 for the full list):
password-reset token testing and JWT tampering need either a real
password-reset email flow or a captured token to mutate — both are
per-site enough that they belong in a one-off script using `auth.py`'s
adapters directly, not a generic check.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from security_toolkit.config import Credentials, Target
from security_toolkit.recon.auth import AuthProvider
from security_toolkit.recon.rate_limit_check import RateLimitResult, check_rate_limiting
from security_toolkit.scope_guard import resolve_in_scope_url


@dataclass(frozen=True)
class SessionFixationResult:
    logged_in: bool
    session_cookie_changed: bool
    flagged: bool
    detail: str


@dataclass(frozen=True)
class LogoutResult:
    before_logout_status: int
    after_logout_status: int
    flagged: bool
    detail: str


def check_session_fixation(
    target: Target, provider: AuthProvider, credentials: Credentials, timeout: float = 10.0
) -> SessionFixationResult:
    """Visit the site anonymously first (picking up whatever session
    cookie it hands out to a logged-out visitor), then log in on that same
    session. Flags if the cookie(s) are unchanged — the classic session
    fixation signal: an attacker-supplied pre-auth session ID stays valid
    after the victim authenticates on it.
    """
    session = requests.Session()
    session.get(resolve_in_scope_url(target, "/"), timeout=timeout)
    pre_login_cookies = dict(session.cookies)

    result = provider.login(session, credentials)
    post_login_cookies = dict(session.cookies)

    unchanged = bool(pre_login_cookies) and pre_login_cookies == post_login_cookies
    flagged = result.logged_in and unchanged
    detail = (
        "FLAGGED: the pre-login session cookie(s) were still valid after login — "
        "possible session fixation."
        if flagged
        else "OK: session identifier changed on login, or no pre-login cookie existed to fixate."
    )
    return SessionFixationResult(
        logged_in=result.logged_in, session_cookie_changed=not unchanged, flagged=flagged, detail=detail
    )


def check_logout_invalidation(
    target: Target,
    session: requests.Session,
    logout_path: str,
    protected_path: str,
    logout_method: str = "get",
    timeout: float = 10.0,
) -> LogoutResult:
    """On an already-logged-in session: confirm a protected page is
    reachable, hit logout, then request the same protected page again on
    the same session/token. Flags if it's still reachable — logout didn't
    actually invalidate anything server-side.
    """
    protected_url = resolve_in_scope_url(target, protected_path)
    logout_url = resolve_in_scope_url(target, logout_path)

    before = session.get(protected_url, timeout=timeout)

    logout_call = session.post if logout_method.lower() == "post" else session.get
    logout_call(logout_url, timeout=timeout)

    after = session.get(protected_url, timeout=timeout)

    flagged = 200 <= after.status_code < 300
    detail = (
        f"before_logout={before.status_code} after_logout={after.status_code}. "
        + (
            "FLAGGED: the session/token still works after logout."
            if flagged
            else "OK: the session/token was rejected after logout."
        )
    )
    return LogoutResult(
        before_logout_status=before.status_code,
        after_logout_status=after.status_code,
        flagged=flagged,
        detail=detail,
    )


def check_login_rate_limiting(
    provider: AuthProvider,
    bad_credentials: Credentials,
    max_attempts: int = 10,
) -> RateLimitResult:
    """Attempt a login with known-bad credentials repeatedly. Flags if
    none of the attempts come back with a sign of throttling (HTTP 429)
    — i.e. the login form can be retried indefinitely, which is what
    makes credential-stuffing/brute-force practical.

    Thin wrapper around `rate_limit_check.check_rate_limiting` — the
    same probe backs the IDOR/injection/upload testers' automatic
    rate-limit checks, so every endpoint this toolkit touches gets this
    signal, not just login.
    """
    return check_rate_limiting(
        "login", lambda: provider.login(requests.Session(), bad_credentials), max_attempts=max_attempts
    )
