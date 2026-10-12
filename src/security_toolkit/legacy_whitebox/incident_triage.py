"""LEGACY / WHITE-BOX ONLY — see legacy_whitebox/__init__.py.

Phase 1 (security-playbook.md) incident-triage checks. Needs a filesystem
path on the app's server (`wp_path`) and direct DB credentials — access
the security team does not have under the black-box testing agreement.
Not part of the normal workflow; kept only for a possible future
white-box/internal engagement.

These functions only DETECT and REPORT. None of them delete files, revoke
accounts, or rotate credentials — those steps in the playbook stay manual,
on purpose, because a human needs to confirm each one before it happens.
Run this against a backup/snapshot of the suspected-compromised site, not
the live site, per Phase 1 step 1.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from security_toolkit.config import DBConfig

# Common webshell / backdoor signatures. Not exhaustive — this flags for
# human review, it does not replace Wordfence/Sucuri/ClamAV from the
# playbook's step 5.
WEBSHELL_PATTERNS = (
    re.compile(rb"eval\s*\(\s*base64_decode", re.IGNORECASE),
    re.compile(rb"system\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
    re.compile(rb"passthru\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
    re.compile(rb"assert\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
    re.compile(rb"FilesMan|c99shell|r57shell|WSO\s*Shell", re.IGNORECASE),
    re.compile(rb"preg_replace\s*\(.*?/e['\"]", re.IGNORECASE),
)


@dataclass(frozen=True)
class ModifiedFile:
    path: str
    modified_at: float


@dataclass(frozen=True)
class FlaggedFile:
    path: str
    matched_pattern: str


@dataclass(frozen=True)
class RogueAdmin:
    user_id: int
    user_login: str
    user_registered: str


def _validate_wp_path(wp_path: str) -> Path:
    path = Path(wp_path)
    if not path.exists() or not path.is_dir():
        raise ValueError(f"wp_path does not exist or is not a directory: {wp_path}")
    return path


def find_recently_modified_php(wp_path: str, days: int = 30) -> tuple[ModifiedFile, ...]:
    """List .php files modified within the last `days` days."""
    root = _validate_wp_path(wp_path)
    if days <= 0:
        raise ValueError("days must be a positive integer")
    cutoff = days * 86400
    import time

    now = time.time()
    found = []
    for php_file in root.rglob("*.php"):
        try:
            mtime = php_file.stat().st_mtime
        except OSError:
            continue
        if now - mtime <= cutoff:
            found.append(ModifiedFile(path=str(php_file), modified_at=mtime))
    return tuple(sorted(found, key=lambda item: item.modified_at, reverse=True))


def find_php_in_uploads(wp_path: str) -> tuple[str, ...]:
    """Flag any .php file under wp-content/uploads — that directory should
    never be able to execute PHP, so a hit here is a strong backdoor signal.
    """
    root = _validate_wp_path(wp_path)
    uploads = root / "wp-content" / "uploads"
    if not uploads.exists():
        return ()
    return tuple(str(path) for path in uploads.rglob("*.php"))


def scan_for_webshell_signatures(paths: tuple[str, ...]) -> tuple[FlaggedFile, ...]:
    """Grep a set of file paths for known webshell/backdoor signatures."""
    flagged = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            content = path.read_bytes()
        except OSError:
            continue
        for pattern in WEBSHELL_PATTERNS:
            if pattern.search(content):
                flagged.append(FlaggedFile(path=str(path), matched_pattern=pattern.pattern.decode()))
                break
    return tuple(flagged)


def run_core_checksum_verify(wp_path: str, wp_cli_bin: str = "wp") -> tuple[bool, str]:
    """Run `wp core verify-checksums` and return (passed, output).

    Requires WP-CLI to be installed and `wp_path` to be a real WordPress
    install. Never shells out with untrusted input — wp_path must come from
    config/scope.json, and `wp_cli_bin` is only ever a fixed binary name.
    """
    root = _validate_wp_path(wp_path)
    try:
        result = subprocess.run(
            [wp_cli_bin, "core", "verify-checksums", f"--path={root}"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"'{wp_cli_bin}' not found. Install WP-CLI or pass wp_cli_bin=... "
            "to point at it."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("wp core verify-checksums timed out after 120s") from exc
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output.strip()


def find_rogue_admin_accounts(
    db_config: DBConfig, known_admin_logins: tuple[str, ...]
) -> tuple[RogueAdmin, ...]:
    """Query wp_users/wp_usermeta for admin accounts not in the known list.

    This is read-only (SELECT only) and uses parameterized queries — it
    never interpolates user-controlled strings into SQL.
    """
    import pymysql

    query = """
        SELECT u.ID, u.user_login, u.user_registered
        FROM wp_users u
        JOIN wp_usermeta m ON m.user_id = u.ID
        WHERE m.meta_key = 'wp_capabilities'
          AND m.meta_value LIKE %s
    """
    connection = pymysql.connect(
        host=db_config.host,
        port=db_config.port,
        user=db_config.user,
        password=db_config.password,
        database=db_config.name,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, ("%administrator%",))
            rows = cursor.fetchall()
    finally:
        connection.close()

    known = {login.lower() for login in known_admin_logins}
    return tuple(
        RogueAdmin(
            user_id=row["ID"],
            user_login=row["user_login"],
            user_registered=str(row["user_registered"]),
        )
        for row in rows
        if row["user_login"].lower() not in known
    )
