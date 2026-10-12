"""Phase 4.4 (security-playbook.md) IDOR helper — the two-account horizontal
privilege-escalation test, automated across a list of endpoints.

GET-only by default: this confirms IDOR by reading data as the "wrong"
user, it does not write/delete anything unless `allow_mutations=True` is
passed explicitly per test case (use that only for a disposable staging
account's own data, per the playbook's safety rule).

Every URL this module hits must start with the authorized target's
`base_url` from config/scope.json — see `require_in_scope`.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from security_toolkit.config import Target
from security_toolkit.scope_guard import OutOfScopeError, require_in_scope, resolve_in_scope_url

__all__ = [
    "OutOfScopeError",
    "require_in_scope",
    "IdorTestCase",
    "IdorResult",
    "run_idor_test",
    "run_idor_suite",
]


@dataclass(frozen=True)
class IdorTestCase:
    name: str
    url_template: str  # must contain "{id}", e.g. "/api/orders/{id}"
    owner_id: str  # an ID that belongs to session_a (the resource's real owner)
    allow_mutations: bool = False  # True only to test PATCH/DELETE, not just GET


@dataclass(frozen=True)
class IdorResult:
    name: str
    url: str
    owner_status: int
    other_user_status: int
    flagged: bool
    detail: str


def _resolve_url(target: Target, url_template: str, resource_id: str) -> str:
    return resolve_in_scope_url(target, url_template.format(id=resource_id))


def run_idor_test(
    target: Target,
    session_owner: requests.Session,
    session_other: requests.Session,
    test_case: IdorTestCase,
    timeout: float = 10.0,
) -> IdorResult:
    """Request the owner's resource as both the owner and a different
    logged-in user. Flags if the other user also gets a successful (2xx)
    response — that's a confirmed horizontal IDOR.
    """
    url = _resolve_url(target, test_case.url_template, test_case.owner_id)

    owner_response = session_owner.get(url, timeout=timeout)
    other_response = session_other.get(url, timeout=timeout)

    flagged = 200 <= other_response.status_code < 300
    detail = (
        f"owner={owner_response.status_code} other_user={other_response.status_code}. "
        + (
            "FLAGGED: the second account received a successful response for "
            "a resource it doesn't own."
            if flagged
            else "OK: the second account was denied as expected."
        )
    )
    return IdorResult(
        name=test_case.name,
        url=url,
        owner_status=owner_response.status_code,
        other_user_status=other_response.status_code,
        flagged=flagged,
        detail=detail,
    )


def run_idor_suite(
    target: Target,
    session_owner: requests.Session,
    session_other: requests.Session,
    test_cases: list[IdorTestCase],
) -> tuple[IdorResult, ...]:
    return tuple(
        run_idor_test(target, session_owner, session_other, case) for case in test_cases
    )
