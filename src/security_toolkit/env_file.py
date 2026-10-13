"""Read/update a .env file's KEY=value lines without disturbing anything
else in it (comments, unrelated vars, ordering). Used to write generated
test-account credentials in automatically instead of asking someone to
paste them in by hand.
"""

from __future__ import annotations

from pathlib import Path


def update_env_file(path: Path, updates: dict[str, str]) -> None:
    """Set each key in `updates` to its value, adding the line if the key
    isn't already present. Every other line in the file is left exactly
    as-is.
    """
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(updates)
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                new_lines.append(f"{key}={remaining.pop(key)}")
                continue
        new_lines.append(line)

    for key, value in remaining.items():
        new_lines.append(f"{key}={value}")

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
