"""Shared, dependency-free HTML `<form>` parsing for black-box auto-detection
(login forms in auth_detect.py, registration forms in provision.py).
Plain regex — this toolkit only ever reads a form's own field names/types/
values, never arbitrary HTML, so a full parser would be overkill.
"""

from __future__ import annotations

import re

# Hidden-field names commonly used for CSRF tokens across frameworks.
CSRF_FIELD_CANDIDATES = (
    "_token",  # Laravel
    "csrf_token",
    "csrfmiddlewaretoken",  # Django
    "authenticity_token",  # Rails
    "__requestverificationtoken",  # ASP.NET
)


class FormParsingError(RuntimeError):
    """Raised when no usable <form> could be found/parsed on a page."""


def find_form_with_password_field(page_html: str) -> str:
    """Return the first <form> block that contains a password-type input.

    Login and registration pages often have more than one <form> on the
    page (e.g. a newsletter signup in the footer) — the password field is
    the reliable signal for "this is the one we want."
    """
    forms = re.findall(r"<form\b.*?</form>", page_html, re.IGNORECASE | re.DOTALL)
    for form_html in forms:
        if re.search(r'<input\b[^>]*type=["\']password["\']', form_html, re.IGNORECASE):
            return form_html
    raise FormParsingError(
        "No <form> containing a password field was found on this page — "
        "it may be a JS-rendered form (not plain HTML) or a JSON API."
    )


def extract_inputs(form_html: str) -> list[dict]:
    """Return every <input>'s name/type/value from a form block."""
    inputs = []
    for tag in re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE):
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if not name_match:
            continue
        type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        value_match = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        inputs.append(
            {
                "name": name_match.group(1),
                "type": (type_match.group(1).lower() if type_match else "text"),
                "value": value_match.group(1) if value_match else "",
            }
        )
    return inputs


def find_form_action(form_html: str, fallback_url: str) -> str:
    """Return the form's `action` URL, or `fallback_url` if it has none
    (meaning it submits to the page it's on, per HTML's own default).
    """
    match = re.search(r'<form\b[^>]*\baction=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
    return match.group(1) if match else fallback_url
