#!/usr/bin/env python3
"""CLI: add/list/remove test-account credentials in the MongoDB store.

Use this when a target's registration is invite-only and
provision_test_accounts.py can't create accounts automatically — get the
two accounts' credentials from the dev team (never code/server access,
just the credentials) and store them here.

Usage:
    python scripts/manage_credentials.py add --target cheerlytics --label IDOR_USER_A --username a@test.com --password ...
    python scripts/manage_credentials.py list --target cheerlytics
    python scripts/manage_credentials.py remove --target cheerlytics --label IDOR_USER_A
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.credentials_db import delete_credentials, list_credentials, save_credentials


def cmd_add(args: argparse.Namespace) -> int:
    username = args.username or input("Username/email: ").strip()
    password = args.password or input("Password: ").strip()
    if not username or not password:
        print("ERROR: username and password are both required.", file=sys.stderr)
        return 1
    save_credentials(args.target, args.label, username, password, uri=args.mongodb_uri)
    print(f"Saved credentials for target '{args.target}' label '{args.label}'.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    creds = list_credentials(args.target, uri=args.mongodb_uri)
    if not creds:
        scope = f" for target '{args.target}'" if args.target else ""
        print(f"No credentials stored{scope}.")
        return 0
    for item in creds:
        print(f"- {item.target_name} / {item.label}: {item.username}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    removed = delete_credentials(args.target, args.label, uri=args.mongodb_uri)
    if removed == 0:
        print(f"Nothing found for target '{args.target}'" + (f" label '{args.label}'" if args.label else "") + ".")
        return 1
    print(f"Removed {removed} credential(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mongodb-uri", help="Override MONGODB_URI from .env")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add or update a credential")
    add_parser.add_argument("--target", required=True)
    add_parser.add_argument("--label", required=True, help="e.g. IDOR_USER_A")
    add_parser.add_argument("--username")
    add_parser.add_argument("--password")
    add_parser.set_defaults(func=cmd_add)

    list_parser = subparsers.add_parser("list", help="List stored credentials (usernames only, not passwords)")
    list_parser.add_argument("--target", help="Limit to one target; omit to list all")
    list_parser.set_defaults(func=cmd_list)

    remove_parser = subparsers.add_parser("remove", help="Remove one label, or every label for a target")
    remove_parser.add_argument("--target", required=True)
    remove_parser.add_argument("--label", help="Omit to remove every credential for this target")
    remove_parser.set_defaults(func=cmd_remove)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
