"""Resolve "data.token"-style dotted paths against a parsed JSON body.
Shared by `recon/auth.py` (reading a login response's token field) and
`recon/upload_testing.py` (reading an upload response's file-URL field)
— same tree-walk, different miss behavior, so this returns `None` on a
miss and each caller decides whether that's an error.
"""

from __future__ import annotations

from typing import Any


def lookup_dotted_path(data: dict, dotted_path: str) -> Any | None:
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
