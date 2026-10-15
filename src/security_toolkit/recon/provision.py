"""Create the two disposable test accounts (User A, User B) that the IDOR
suite needs, per Phase 4.1 of the playbook — black-box only: everything
here goes through the app's own public HTTP surface, never a server shell
or DB write.

- **A JSON API signup endpoint** (most custom Node/Express apps):
  automatable via `register_via_api`, the same data-driven approach as
  `auth.py`'s login adapters — POST a JSON payload to the signup route.
- **An HTML registration form** (most Laravel/PHP apps, some WordPress
  sites): automatable via `register_via_form`, which auto-detects the
  form's fields the same way `auth_detect.py` auto-detects a login form
  — no field names need to be known in advance, just the register URL.
- **Anything behind invite-only or admin-created accounts**: not
  automatable from outside the app, by definition of black-box — ask the
  dev team to create the two accounts (without sharing any code/access
  back), then store the credentials in `.env` as documented in README.md.
  This module does not try to guess that path for you.

(WP-CLI-based provisioning, which needs a server shell, lives in
`legacy_whitebox.provision` — not usable under a black-box engagement.)

Every function here only writes to a target resolved through
`security_toolkit.config.load_authorized_target` — never call
`register_via_api` with a URL that didn't come from the target's scope entry.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from security_toolkit.recon.html_forms import FormParsingError, extract_inputs, find_form_action, find_form_with_password_field


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


def _field_value_for(field_name: str, email: str, identity_value: str, password: str, field_type: str, existing_value: str) -> str:
    """Best-effort guess at what to put in one registration field, from
    its name/type alone. Covers the common cases (email, name/username,
    password, password confirmation, a "terms accepted" checkbox); an
    unusual required field (e.g. a phone number in a specific format)
    may still cause the submission to be rejected — the result will say
    so rather than silently continuing.
    """
    lowered = field_name.lower()
    if field_type == "password":
        return password
    if field_type == "checkbox":
        return existing_value or "1"  # e.g. "accept terms" checkboxes
    if "email" in lowered:
        return email
    if "name" in lowered or "user" in lowered:
        return identity_value
    return existing_value or identity_value


def register_via_form(
    register_url: str,
    email: str,
    identity_value: str,
    password: str | None = None,
    timeout: float = 10.0,
) -> ProvisionResult:
    """Auto-detect and submit a site's own HTML registration form.

    GETs `register_url`, finds the <form> with a password field (same
    approach as `auth_detect.detect_auth_config`), fills every field with
    a best-effort value (see `_field_value_for`), and POSTs it on the same
    session so any CSRF token/cookie pairing stays valid. If the form has
    two password fields (password + confirmation), both get the same
    generated password.
    """
    password = password or generate_test_password()
    session = requests.Session()

    response = session.get(register_url, timeout=timeout)
    if response.status_code >= 400:
        raise RuntimeError(f"GET {register_url} returned status {response.status_code}")

    try:
        form_html = find_form_with_password_field(response.text)
    except FormParsingError as exc:
        raise RuntimeError(str(exc)) from exc

    payload = {}
    for field in extract_inputs(form_html):
        if field["type"] == "submit":
            continue
        payload[field["name"]] = _field_value_for(
            field["name"], email, identity_value, password, field["type"], field["value"]
        )

    action_url = urljoin(register_url, find_form_action(form_html, register_url))
    post_response = session.post(action_url, data=payload, timeout=timeout)

    if post_response.status_code >= 400:
        raise RuntimeError(
            f"registration failed (status {post_response.status_code}): {post_response.text[:300]}"
        )

    return ProvisionResult(
        username=identity_value,
        email=email,
        password=password,
        detail=f"registered via {action_url} (status {post_response.status_code})",
    )


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
