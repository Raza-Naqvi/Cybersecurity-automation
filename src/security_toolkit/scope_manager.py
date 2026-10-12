"""Pure logic for reading/writing config/scope.json, kept separate from
the interactive CLI in scripts/manage_scope.py so it's testable without
mocking stdin.

Every function here returns a new dict rather than mutating the one it
was given — scope.json is small, and immutable updates make it obvious
nothing is shared/mutated by accident between calls.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_scope_data(path: Path) -> dict:
    """Load scope.json, or an empty-but-valid structure if it doesn't exist yet."""
    if not path.exists():
        return {"authorized_targets": []}
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("authorized_targets", [])
    return data


def list_target_names(data: dict) -> tuple[str, ...]:
    return tuple(target.get("name", "") for target in data.get("authorized_targets", []))


def get_target(data: dict, name: str) -> dict | None:
    for target in data.get("authorized_targets", []):
        if target.get("name") == name:
            return target
    return None


def upsert_target(data: dict, target: dict) -> dict:
    """Return a new scope dict with `target` added, or replacing the
    existing entry of the same name.
    """
    if "name" not in target or not target["name"]:
        raise ValueError("target must have a non-empty 'name'")
    remaining = [t for t in data.get("authorized_targets", []) if t.get("name") != target["name"]]
    return {**data, "authorized_targets": [*remaining, target]}


def remove_target(data: dict, name: str) -> dict:
    """Return a new scope dict with the named target removed (no-op if absent)."""
    remaining = [t for t in data.get("authorized_targets", []) if t.get("name") != name]
    return {**data, "authorized_targets": remaining}


def save_scope_data(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


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
