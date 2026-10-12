"""Create the two disposable test accounts (User A, User B) that the IDOR
suite needs, per Phase 4.1 of the playbook — black-box only: everything
here goes through the app's own public HTTP surface, never a server shell
or DB write.

- **A site with a public self-serve signup endpoint** (Laravel, Node, or
  WordPress with open registration): automatable via `register_via_api`,
  the same data-driven approach as `auth.py`'s login adapters — POST a
  JSON payload to the signup route.
- **Anything behind invite-only or admin-created accounts**: not
  automatable from outside the app, by definition of black-box — ask the
  dev team to create the two accounts (without sharing any code/access
  back), then store the credentials in `.env` as documented in README.md.
  This module does not try to guess that path for you.

(WP-CLI-based provisioning, which needs a server shell, lives in
`legacy_whitebox.provision` — not usable under a black-box engagement.)

Every function here only writes to a target resolved through
`security_toolkit.config.load_authorized_target` — never call
`register_via_api` with a URL that didn't come from scope.json.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class ProvisionResult:
    username: str
    email: str
    password: str
    detail: str


def generate_test_password(length: int = 20) -> str:
    """A random password for a disposable test account, not a real user's."""
    if length < 12:
        raise ValueError("length must be at least 12 for a usable test password")
    return secrets.token_urlsafe(length)[:length]


def register_via_api(
    register_url: str,
    payload: dict,
    success_status_max: int = 299,
    timeout: float = 10.0,
) -> ProvisionResult:
    """POST a signup payload to a site's own registration endpoint.

    `payload` must already include whatever fields that endpoint expects
    (name/email/password, etc.) — this makes no assumption about field
    names, since that's exactly the part that differs per app. Raises if
    the endpoint doesn't return success; it never retries or guesses at a
    different shape.
    """
    response = requests.post(register_url, json=payload, timeout=timeout)
    if response.status_code > success_status_max:
        raise RuntimeError(f"registration failed (status {response.status_code}): {response.text[:300]}")
    return ProvisionResult(
        username=str(payload.get("username") or payload.get("email") or "unknown"),
        email=str(payload.get("email", "")),
        password=str(payload.get("password", "")),
        detail=f"registered via {register_url} (status {response.status_code})",
    )
