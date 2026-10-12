#!/usr/bin/env python3
"""CLI: add/list/remove targets in config/scope.json — no manual JSON
editing. Interactive by default (just answer the prompts); pass flags
instead for non-interactive/scripted use.

Usage:
    python scripts/manage_scope.py add              # guided prompts
    python scripts/manage_scope.py add --name foo --base-url https://... --no-interactive
    python scripts/manage_scope.py list
    python scripts/manage_scope.py remove --name foo
"""

from __future__ import annotations

import argparse
import sys

from security_toolkit.config import DEFAULT_SCOPE_PATH
from security_toolkit.recon.auth_detect import AuthDetectionError, detect_auth_config
from security_toolkit.scope_manager import (
    build_auth_block,
    list_target_names,
    load_scope_data,
    remove_target,
    save_scope_data,
    upsert_target,
)


def _prompt(text: str, default: str | None = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{text}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if not value and not required:
            return ""
        if value:
            return value
        print("  (required — try again)")


def _collect_auth_block(args: argparse.Namespace) -> dict | None:
    auth_type = args.auth_type
    if auth_type is None and not args.no_interactive:
        auth_type = _prompt(
            "Set up login for the IDOR/auth testers now? (none/auto/wordpress/form_session/json_token)",
            default="auto",
        )
    if not auth_type or auth_type == "none":
        return None

    login_url = args.login_url
    if login_url is None and not args.no_interactive:
        login_url = _prompt("Login URL")
    if not login_url:
        print("ERROR: --login-url is required to set up auth.", file=sys.stderr)
        raise SystemExit(1)

    if auth_type == "auto":
        try:
            block = detect_auth_config(login_url)
        except AuthDetectionError as exc:
            print(f"ERROR: couldn't auto-detect a login form at {login_url}: {exc}", file=sys.stderr)
            print("Re-run with --auth-type wordpress/form_session/json_token and set the fields by hand.", file=sys.stderr)
            raise SystemExit(1) from exc
        print(f"Auto-detected: {block}")
        return block

    username_field = args.username_field or "username"
    password_field = args.password_field or "password"
    csrf_page_url = args.csrf_page_url
    csrf_field_name = args.csrf_field_name

    if auth_type == "form_session" and not args.no_interactive:
        username_field = _prompt("Username/email field name", default=username_field)
        password_field = _prompt("Password field name", default=password_field)
        wants_csrf = _prompt("Does the login form carry a CSRF token (most Laravel apps do)? (y/n)", default="y")
        if wants_csrf.lower().startswith("y"):
            csrf_page_url = csrf_page_url or _prompt("Page to fetch the CSRF token from", default=login_url)
            csrf_field_name = csrf_field_name or _prompt("CSRF hidden field name", default="_token")

    if auth_type == "json_token" and not args.no_interactive:
        username_field = _prompt("Username/email field name", default=username_field)
        password_field = _prompt("Password field name", default=password_field)
        token_path = _prompt("Dotted path to the token in the login response JSON", default=args.token_path or "token")
        args.token_path = token_path

    return build_auth_block(
        auth_type=auth_type,
        login_url=login_url,
        username_field=username_field,
        password_field=password_field,
        csrf_page_url=csrf_page_url,
        csrf_field_name=csrf_field_name,
        token_path=args.token_path or "token",
        header_name=args.header_name or "Authorization",
        header_prefix=args.header_prefix or "Bearer ",
    )


def cmd_add(args: argparse.Namespace) -> int:
    data = load_scope_data(DEFAULT_SCOPE_PATH)

    name = args.name
    if name is None and not args.no_interactive:
        name = _prompt("Target name (what you'll pass to --target)")
    if not name:
        print("ERROR: --name is required.", file=sys.stderr)
        return 1

    if name in list_target_names(data) and not args.force:
        if args.no_interactive:
            print(f"ERROR: '{name}' already exists. Pass --force to overwrite.", file=sys.stderr)
            return 1
        confirm = input(f"'{name}' already exists — overwrite? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return 1

    base_url = args.base_url
    if base_url is None and not args.no_interactive:
        base_url = _prompt("Base URL (e.g. https://staging.example.com)")
    if not base_url:
        print("ERROR: --base-url is required.", file=sys.stderr)
        return 1

    site_type = args.type
    if site_type is None and not args.no_interactive:
        site_type = _prompt("Site type (wordpress/laravel/node/custom)", default="custom")
    site_type = site_type or "custom"

    environment = args.environment
    if environment is None and not args.no_interactive:
        environment = _prompt("Environment", default="staging")
    environment = environment or "staging"

    notes = args.notes
    if notes is None and not args.no_interactive:
        notes = _prompt("Notes (optional)", default="", required=False)
    notes = notes or ""

    known_admins = tuple(
        login.strip() for login in (args.known_admin_logins or "").split(",") if login.strip()
    )

    target: dict = {
        "name": name,
        "type": site_type,
        "environment": environment,
        "wp_path": args.wp_path,
        "base_url": base_url,
        "known_admin_logins": list(known_admins),
        "notes": notes,
    }

    auth_block = _collect_auth_block(args)
    if auth_block:
        target["auth"] = auth_block

    data = upsert_target(data, target)
    save_scope_data(DEFAULT_SCOPE_PATH, data)
    print(f"Saved target '{name}' to {DEFAULT_SCOPE_PATH}")
    print(f"Run it with, e.g.: python scripts/run_recon.py --target {name}")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    data = load_scope_data(DEFAULT_SCOPE_PATH)
    names = list_target_names(data)
    if not names:
        print("No targets configured yet. Run: python scripts/manage_scope.py add")
        return 0
    for name in names:
        print(f"- {name}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    data = load_scope_data(DEFAULT_SCOPE_PATH)
    if args.name not in list_target_names(data):
        print(f"'{args.name}' not found.", file=sys.stderr)
        return 1
    data = remove_target(data, args.name)
    save_scope_data(DEFAULT_SCOPE_PATH, data)
    print(f"Removed '{args.name}'.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add or update a target")
    add_parser.add_argument("--name")
    add_parser.add_argument("--base-url")
    add_parser.add_argument("--type")
    add_parser.add_argument("--environment")
    add_parser.add_argument("--wp-path")
    add_parser.add_argument("--notes")
    add_parser.add_argument("--known-admin-logins", help="Comma-separated")
    add_parser.add_argument("--auth-type", choices=["none", "auto", "wordpress", "form_session", "json_token"])
    add_parser.add_argument("--login-url")
    add_parser.add_argument("--username-field")
    add_parser.add_argument("--password-field")
    add_parser.add_argument("--csrf-page-url")
    add_parser.add_argument("--csrf-field-name")
    add_parser.add_argument("--token-path")
    add_parser.add_argument("--header-name")
    add_parser.add_argument("--header-prefix")
    add_parser.add_argument("--force", action="store_true", help="Overwrite an existing target with the same name")
    add_parser.add_argument("--no-interactive", action="store_true", help="Fail on missing required flags instead of prompting")
    add_parser.set_defaults(func=cmd_add)

    list_parser = subparsers.add_parser("list", help="List configured target names")
    list_parser.set_defaults(func=cmd_list)

    remove_parser = subparsers.add_parser("remove", help="Remove a target by name")
    remove_parser.add_argument("--name", required=True)
    remove_parser.set_defaults(func=cmd_remove)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
