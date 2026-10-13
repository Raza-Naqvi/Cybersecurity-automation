"""Auto-detect a `form_session`/`wordpress` auth block from a login page,
the way we did manually with curl+grep: GET the login URL, find the
`<form>` that contains a password field, and read off its field names
and (if present) CSRF hidden field.

Black-box only — a plain GET against the app's own public login page,
nothing else.

Scope: HTML, server-rendered login forms only (covers WordPress and most
Laravel/PHP apps). A JSON API login (`json_token`) can't be auto-detected
this way — there's no form to read field names from — so that type still
needs to be configured by hand with `--auth-type json_token`.
"""

from __future__ import annotations

import requests

from security_toolkit.recon.html_forms import (
    CSRF_FIELD_CANDIDATES,
    FormParsingError,
    extract_inputs,
    find_form_with_password_field,
)

# Field names commonly used for the login identifier, in priority order.
USERNAME_FIELD_CANDIDATES = ("email", "username", "user_login", "login", "user")


class AuthDetectionError(RuntimeError):
    """Raised when the login page's form couldn't be parsed into an auth block."""


def detect_auth_config(login_url: str, timeout: float = 10.0) -> dict:
    """Fetch `login_url` and build the matching `auth` block automatically.

    Returns a `wordpress` block if the form's fields are WordPress's
    standard `log`/`pwd`, otherwise a `form_session` block built from
    whatever field names the form actually uses.
    """
    response = requests.get(login_url, timeout=timeout)
    if response.status_code >= 400:
        raise AuthDetectionError(f"GET {login_url} returned status {response.status_code}")

    try:
        form_html = find_form_with_password_field(response.text)
    except FormParsingError as exc:
        raise AuthDetectionError(
            f"{exc} Set up --auth-type json_token or form_session manually instead."
        ) from exc
    inputs = extract_inputs(form_html)

    password_field = next((i["name"] for i in inputs if i["type"] == "password"), None)
    if not password_field:
        raise AuthDetectionError("Found a form but no password-type field inside it.")

    if password_field == "pwd" and any(i["name"] == "log" for i in inputs):
        return {"type": "wordpress", "login_url": login_url}

    csrf_field = next(
        (i["name"] for i in inputs if i["type"] == "hidden" and i["name"].lower() in CSRF_FIELD_CANDIDATES),
        None,
    )

    username_field = None
    for candidate in USERNAME_FIELD_CANDIDATES:
        if any(i["name"] == candidate and i["type"] != "hidden" for i in inputs):
            username_field = candidate
            break
    if not username_field:
        # Fall back to the first non-hidden, non-password text-like field.
        username_field = next(
            (i["name"] for i in inputs if i["type"] in ("text", "email") and i["name"] != password_field),
            "username",
        )

    block: dict = {
        "type": "form_session",
        "login_url": login_url,
        "username_field": username_field,
        "password_field": password_field,
    }
    if csrf_field:
        block["csrf"] = {"page_url": login_url, "field_name": csrf_field}
    return block
