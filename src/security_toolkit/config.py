"""Scope and environment configuration.

This module is the single authorization gate: every check in this toolkit
must resolve its target through `load_authorized_target`, which refuses to
return anything not explicitly listed in config/scope.json. Never bypass
this by hardcoding a path or URL directly in a script.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCOPE_PATH = REPO_ROOT / "config" / "scope.json"


class ScopeError(RuntimeError):
    """Raised when a requested target isn't in the authorized scope file."""


@dataclass(frozen=True)
class Target:
    name: str
    type: str
    environment: str
    wp_path: str | None
    base_url: str | None
    known_admin_logins: tuple[str, ...]
    notes: str
    # Raw auth config block from scope.json (schema varies by `auth["type"]`);
    # see security_toolkit.recon.auth.build_auth_provider for the schema per type.
    auth: dict | None = None


@dataclass(frozen=True)
class DBConfig:
    host: str
    port: int
    name: str
    user: str
    password: str


def load_env(dotenv_path: Path | None = None) -> None:
    """Load variables from .env into the process environment, if present."""
    load_dotenv(dotenv_path=dotenv_path or (REPO_ROOT / ".env"))


def load_db_config() -> DBConfig:
    """Build DB connection settings from environment variables only.

    Never hardcode credentials; this raises if required values are missing
    so a misconfigured run fails fast instead of silently using defaults.
    """
    load_env()
    required = ["DB_HOST", "DB_NAME", "DB_USER"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise ScopeError(
            f"Missing required DB environment variables: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in real values."
        )
    return DBConfig(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "3306")),
        name=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ.get("DB_PASSWORD", ""),
    )


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str


def load_credentials_from_env(prefix: str) -> Credentials:
    """Read a {prefix}_USERNAME / {prefix}_PASSWORD pair from the environment.

    Used for the IDOR tester's two test accounts, e.g. prefix="IDOR_USER_A".
    Never put real credentials in scope.json or in code — only in .env.
    """
    load_env()
    username_key, password_key = f"{prefix}_USERNAME", f"{prefix}_PASSWORD"
    username, password = os.environ.get(username_key), os.environ.get(password_key)
    if not username or not password:
        raise ScopeError(
            f"Missing {username_key}/{password_key} in the environment. "
            "Add them to .env (never to scope.json or source code)."
        )
    return Credentials(username=username, password=password)


def _read_scope_file(scope_path: Path) -> list[dict]:
    if not scope_path.exists():
        raise ScopeError(
            f"No scope file at {scope_path}. Copy config/scope.example.json to "
            "config/scope.json and list only systems you're authorized to test."
        )
    with scope_path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    targets = data.get("authorized_targets", [])
    if not isinstance(targets, list):
        raise ScopeError("config/scope.json: 'authorized_targets' must be a list.")
    return targets


def list_authorized_targets(scope_path: Path | None = None) -> tuple[Target, ...]:
    raw_targets = _read_scope_file(scope_path or DEFAULT_SCOPE_PATH)
    return tuple(
        Target(
            name=item["name"],
            type=item.get("type", "unknown"),
            environment=item.get("environment", "unknown"),
            wp_path=item.get("wp_path"),
            base_url=item.get("base_url"),
            known_admin_logins=tuple(item.get("known_admin_logins", [])),
            notes=item.get("notes", ""),
            auth=item.get("auth"),
        )
        for item in raw_targets
    )


def load_authorized_target(name: str, scope_path: Path | None = None) -> Target:
    """Return the named target only if it's explicitly listed in scope.json."""
    targets = list_authorized_targets(scope_path)
    matches = [target for target in targets if target.name == name]
    if not matches:
        known = ", ".join(t.name for t in targets) or "(none configured)"
        raise ScopeError(
            f"'{name}' is not in config/scope.json. Known targets: {known}. "
            "Add it there before running any check against it."
        )
    return matches[0]
