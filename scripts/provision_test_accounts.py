#!/usr/bin/env python3
"""CLI: auto-create the two disposable IDOR/auth test accounts (User A,
User B) via a site's own public registration form, and save their
credentials into the local MongoDB credential store — no manual signup,
no manual .env/file editing.

Only works when registration is open and self-serve (no email
verification gate, no admin approval, no invite code). If it is gated,
this will still create the accounts but they may not be usable until
verified — in that case, ask the dev team for two already-verified test
accounts instead and store them with scripts/manage_credentials.py add.

Black-box only — a real signup through the app's own public form, same
as any other visitor could do. Every account is created on a target
resolved through config/scope.json, and the register URL must be inside
that target's base_url.

Usage:
    python scripts/provision_test_accounts.py --target cheerlytics --register-url https://.../register
"""

from __future__ import annotations

import argparse
import secrets
import sys

from security_toolkit.config import load_authorized_target_cli
from security_toolkit.credentials_db import save_credentials
from security_toolkit.recon.provision import register_via_form
from security_toolkit.scope_guard import OutOfScopeError, require_in_scope


def _unique_identity(label: str) -> tuple[str, str]:
    """A unique email + display-name pair for one disposable test account."""
    suffix = secrets.token_hex(4)
    return f"idortest.{label}.{suffix}@example.com", f"IDOR Test {label.upper()} {suffix}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from the MongoDB scope store (scripts/manage_scope.py)")
    parser.add_argument("--register-url", required=True, help="The site's own public registration page URL")
    parser.add_argument("--mongodb-uri", help="Override MONGODB_URI from .env")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt (for scripted use)")
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    try:
        require_in_scope(args.register_url, target)
    except OutOfScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not args.yes:
        confirm = input(
            f"This will create two real accounts on {target.base_url} via {args.register_url}. Continue? [y/N]: "
        ).strip().lower()
        if confirm != "y":
            print("Aborted.")
            return 1

    email_a, name_a = _unique_identity("a")
    email_b, name_b = _unique_identity("b")

    try:
        result_a = register_via_form(args.register_url, email=email_a, identity_value=name_a)
        print(f"Created User A: {result_a.email} — {result_a.detail}")
        result_b = register_via_form(args.register_url, email=email_b, identity_value=name_b)
        print(f"Created User B: {result_b.email} — {result_b.detail}")
    except RuntimeError as exc:
        print(f"ERROR: registration failed — {exc}", file=sys.stderr)
        print(
            "If this site needs email verification or an invite code, this won't work — "
            "ask the dev team for two already-verified test accounts instead and store them "
            "with scripts/manage_credentials.py add.",
            file=sys.stderr,
        )
        return 1

    save_credentials(target.name, "IDOR_USER_A", result_a.email, result_a.password, uri=args.mongodb_uri)
    save_credentials(target.name, "IDOR_USER_B", result_b.email, result_b.password, uri=args.mongodb_uri)

    print(f"\nCredentials saved to MongoDB for target '{target.name}'.")
    print("Now add some fake data to each account (an order, a profile, a message) before running the IDOR/auth testers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
