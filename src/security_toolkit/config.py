"""Scope and environment configuration.

This module is the single authorization gate: every check in this toolkit
must resolve its target through `load_authorized_target`, which refuses to
return anything not explicitly listed in the authorized-target store
(MongoDB, via `scope_db.py` — see below). Never bypass this by hardcoding
a path or URL directly in a script.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]

# The toolkit's OWN MongoDB state (credentials_db.py, report_index.py,
# scope_db.py) — never the target app's database.
DEFAULT_MONGODB_URI = "mongodb://localhost:27017"
DEFAULT_MONGODB_DB_NAME = "security_toolkit"


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
    # Raw auth config block from the target's scope store entry (schema varies by `auth["type"]`);
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


def load_db_config(dotenv_path: Path | None = None) -> DBConfig:
    """Build DB connection settings from environment variables only.

    Never hardcode credentials; this raises if required values are missing
    so a misconfigured run fails fast instead of silently using defaults.
    `dotenv_path` exists mainly for tests — real callers should rely on
    the default (the project's own `.env`).
    """
    load_env(dotenv_path)
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


def load_credentials_from_env(prefix: str, dotenv_path: Path | None = None) -> Credentials:
    """Read a {prefix}_USERNAME / {prefix}_PASSWORD pair from the environment.

    Superseded by `load_test_credentials` (MongoDB-backed, keyed by
    target name) for the normal workflow — kept for anyone who wants to
    hand-supply a one-off credential pair via .env instead.
    """
    load_env(dotenv_path)
    username_key, password_key = f"{prefix}_USERNAME", f"{prefix}_PASSWORD"
    username, password = os.environ.get(username_key), os.environ.get(password_key)
    if not username or not password:
        raise ScopeError(
            f"Missing {username_key}/{password_key} in the environment. "
            "Add them to .env (never to the scope store or source code)."
        )
    return Credentials(username=username, password=password)


@lru_cache(maxsize=None)
def _mongo_client(uri: str) -> Any:
    from pymongo import MongoClient  # lazy import — pymongo only required when Mongo is actually used

    return MongoClient(uri)


def get_mongo_database(uri: str | None = None, db_name: str | None = None) -> Any:
    """Resolve the toolkit's own MongoDB database (credentials_db.py's and
    report_index.py's shared connection logic) — reusing one cached
    `MongoClient` per URI instead of opening a fresh connection per call.

    Never the target app's database; `MONGODB_URI`/`MONGODB_DB_NAME` are
    the toolkit's own private store, read from the environment (loading
    .env first if neither is already set).
    """
    if uri is None and not os.environ.get("MONGODB_URI"):
        load_env()  # .env isn't loaded automatically anywhere else in the process

    client = _mongo_client(uri or os.environ.get("MONGODB_URI", DEFAULT_MONGODB_URI))
    return client[db_name or os.environ.get("MONGODB_DB_NAME", DEFAULT_MONGODB_DB_NAME)]


def load_test_credentials(target_name: str, label: str, uri: str | None = None) -> Credentials:
    """Read one target's test-account credentials from the local
    MongoDB credential store (see credentials_db.py).

    Raises ScopeError if nothing is stored for this target+label, or if
    the credential store itself couldn't be reached (bad MONGODB_URI,
    auth failure, etc.) — run scripts/doctor.py to check the connection,
    scripts/provision_test_accounts.py to create accounts automatically,
    or scripts/manage_credentials.py add to set them by hand.
    """
    from security_toolkit.credentials_db import load_credentials as _load_from_db

    try:
        stored = _load_from_db(target_name, label, uri=uri)
    except Exception as exc:  # noqa: BLE001 — any Mongo connection/auth failure
        raise ScopeError(
            f"Could not reach the MongoDB credential store: {exc}. Run scripts/doctor.py to check MONGODB_URI."
        ) from exc
    if stored is None:
        raise ScopeError(
            f"No credentials stored for target '{target_name}' label '{label}'. "
            "Run scripts/provision_test_accounts.py, or scripts/manage_credentials.py add, to set them."
        )
    return Credentials(username=stored.username, password=stored.password)


def _target_from_doc(item: dict) -> Target:
    return Target(
        name=item["name"],
        type=item.get("type", "unknown"),
        environment=item.get("environment", "unknown"),
        wp_path=item.get("wp_path"),
        base_url=item.get("base_url"),
        known_admin_logins=tuple(item.get("known_admin_logins", [])),
        notes=item.get("notes", ""),
        auth=item.get("auth"),
    )


def list_authorized_targets() -> tuple[Target, ...]:
    from security_toolkit.scope_db import list_all_targets

    try:
        raw_targets = list_all_targets()
    except Exception as exc:  # noqa: BLE001 — any Mongo connection/auth failure
        raise ScopeError(
            f"Could not reach the MongoDB scope store: {exc}. Run scripts/doctor.py to check MONGODB_URI."
        ) from exc
    return tuple(_target_from_doc(item) for item in raw_targets)


def load_authorized_target(name: str) -> Target:
    """Return the named target only if it's explicitly listed in the
    authorized-target store (MongoDB, shared across every machine
    pointed at the same MONGODB_URI).
    """
    from security_toolkit.scope_db import load_target

    try:
        doc = load_target(name)
    except Exception as exc:  # noqa: BLE001 — any Mongo connection/auth failure
        raise ScopeError(
            f"Could not reach the MongoDB scope store: {exc}. Run scripts/doctor.py to check MONGODB_URI."
        ) from exc
    if doc is None:
        known = ", ".join(t.name for t in list_authorized_targets()) or "(none configured)"
        raise ScopeError(
            f"'{name}' is not in the authorized-target store. Known targets: {known}. "
            "Add it with scripts/manage_scope.py add before running any check against it."
        )
    return _target_from_doc(doc)


def load_authorized_target_cli(name: str) -> Target | None:
    """`load_authorized_target`, with the "print to stderr and return None on
    failure" handling every scripts/run_*.py entrypoint needs identically.

    Callers just do:
        target = load_authorized_target_cli(args.target)
        if target is None:
            return 1
    """
    try:
        return load_authorized_target(name)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
