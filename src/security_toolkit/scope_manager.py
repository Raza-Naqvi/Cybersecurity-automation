"""Pure validation/building logic for `scripts/manage_scope.py`, kept
separate from the interactive CLI so it's testable without mocking
stdin. Storage itself (now MongoDB, see `scope_db.py`) lives there —
this module only builds the `auth` sub-block, which needs no I/O.
"""

from __future__ import annotations


def build_auth_block(
    auth_type: str,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    csrf_page_url: str | None = None,
    csrf_field_name: str | None = None,
    token_path: str = "token",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
) -> dict:
    """Build the `auth` block for one of the three known adapter types.
    Raises ValueError for anything else — that case needs a one-off
    adapter written by hand, see recon/auth.py's docstring.
    """
    if not login_url:
        raise ValueError("login_url is required")

    if auth_type == "wordpress":
        return {"type": "wordpress", "login_url": login_url}

    if auth_type == "form_session":
        block: dict = {
            "type": "form_session",
            "login_url": login_url,
            "username_field": username_field,
            "password_field": password_field,
        }
        if csrf_page_url and csrf_field_name:
            block["csrf"] = {"page_url": csrf_page_url, "field_name": csrf_field_name}
        return block

    if auth_type == "json_token":
        return {
            "type": "json_token",
            "login_url": login_url,
            "username_field": username_field,
            "password_field": password_field,
            "token_path": token_path,
            "header_name": header_name,
            "header_prefix": header_prefix,
        }

    raise ValueError(f"Unknown auth_type '{auth_type}' (expected wordpress/form_session/json_token)")
