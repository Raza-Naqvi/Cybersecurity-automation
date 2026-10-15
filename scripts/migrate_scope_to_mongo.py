#!/usr/bin/env python3
"""CLI: one-time import of an existing local config/scope.json into the
MongoDB scope store (src/security_toolkit/scope_db.py) — run this once
per person who already has a local scope.json from before the move to
Mongo. Read-only against the file; never deletes or modifies it.

Usage:
    python scripts/migrate_scope_to_mongo.py
    python scripts/migrate_scope_to_mongo.py --file path/to/scope.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from security_toolkit.config import REPO_ROOT
from security_toolkit.scope_db import save_target

DEFAULT_PATH = REPO_ROOT / "config" / "scope.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=DEFAULT_PATH, help=f"Path to the old scope.json (default: {DEFAULT_PATH})")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"ERROR: no file at {args.file}", file=sys.stderr)
        return 1

    with args.file.open(encoding="utf-8") as handle:
        data = json.load(handle)
    targets = data.get("authorized_targets", [])
    if not targets:
        print(f"No targets found in {args.file} — nothing to import.")
        return 0

    for target in targets:
        save_target(target)
        print(f"Imported '{target['name']}'")

    print(f"\nImported {len(targets)} target(s) into the MongoDB scope store.")
    print(f"{args.file} was not modified — delete it yourself once you've confirmed `python scripts/manage_scope.py list` shows everything.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
