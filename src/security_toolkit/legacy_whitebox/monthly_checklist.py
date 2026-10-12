"""LEGACY / WHITE-BOX ONLY — see legacy_whitebox/__init__.py.

Needs a filesystem path on the app's server (`wp_path`, a local backup
directory, local `npm audit` against source) and direct DB credentials —
access the security team does not have under the black-box testing
agreement. Not part of the normal workflow; kept only for a possible
future white-box/internal engagement.

Automates the parts of the playbook's "Monthly Recurring Checklist" that
can be checked safely without human judgement. Items that need a human
decision (confirming 2FA is still *enabled* per account, reviewing Stripe
webhook logs, deciding whether a traffic spike is malicious) are flagged
as manual action items in the report instead of guessed at.

Nothing here applies an update or changes anything — it only reports what's
outdated or missing so a human can decide and apply it.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from security_toolkit.config import DBConfig
from security_toolkit.legacy_whitebox.incident_triage import RogueAdmin, find_rogue_admin_accounts

_ACCESS_LOG_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass(frozen=True)
class UpdateStatus:
    core_update_available: bool
    outdated_plugins: tuple[str, ...]
    outdated_themes: tuple[str, ...]
    raw_error: str | None = None


@dataclass(frozen=True)
class NpmAuditSummary:
    project_path: str
    vulnerability_counts: dict  # severity -> count
    raw_error: str | None = None


@dataclass(frozen=True)
class BackupFreshness:
    backup_dir: str
    newest_file: str | None
    age_days: float | None
    is_stale: bool


def _run_wp_json(wp_path: str, args: list[str], wp_cli_bin: str = "wp") -> list | dict:
    try:
        result = subprocess.run(
            [wp_cli_bin, *args, f"--path={wp_path}", "--format=json"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"'{wp_cli_bin}' not found; is WP-CLI installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"wp {' '.join(args)} timed out after 60s") from exc
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "wp-cli call failed").strip())
    output = result.stdout.strip()
    return json.loads(output) if output else []


def check_wp_updates(wp_path: str, wp_cli_bin: str = "wp") -> UpdateStatus:
    """Report outdated core/plugins/themes. Does not apply any update."""
    try:
        core_updates = _run_wp_json(wp_path, ["core", "check-update"], wp_cli_bin)
        plugins = _run_wp_json(wp_path, ["plugin", "list", "--update=available"], wp_cli_bin)
        themes = _run_wp_json(wp_path, ["theme", "list", "--update=available"], wp_cli_bin)
    except RuntimeError as exc:
        return UpdateStatus(
            core_update_available=False,
            outdated_plugins=(),
            outdated_themes=(),
            raw_error=str(exc),
        )
    return UpdateStatus(
        core_update_available=bool(core_updates),
        outdated_plugins=tuple(item.get("name", "unknown") for item in plugins),
        outdated_themes=tuple(item.get("name", "unknown") for item in themes),
    )


def run_npm_audit(project_path: str) -> NpmAuditSummary:
    """Run `npm audit --json` in a project directory and summarize counts.

    npm audit exits non-zero when vulnerabilities are found, so a non-zero
    exit code here is expected and not itself an error — only a missing
    `package.json`/npm binary or malformed JSON is treated as one.
    """
    path = Path(project_path)
    if not (path / "package.json").exists():
        return NpmAuditSummary(
            project_path=project_path,
            vulnerability_counts={},
            raw_error="no package.json found at this path",
        )
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("npm not found; is Node.js installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("npm audit timed out after 180s") from exc
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return NpmAuditSummary(
            project_path=project_path,
            vulnerability_counts={},
            raw_error=(result.stderr or "npm audit returned non-JSON output").strip(),
        )
    counts = data.get("metadata", {}).get("vulnerabilities", {})
    return NpmAuditSummary(project_path=project_path, vulnerability_counts=counts)


def check_backup_freshness(backup_dir: str, max_age_days: int = 2) -> BackupFreshness:
    """Flag if the newest file in a backup directory is older than expected."""
    path = Path(backup_dir)
    if not path.exists():
        return BackupFreshness(backup_dir=backup_dir, newest_file=None, age_days=None, is_stale=True)
    files = [item for item in path.iterdir() if item.is_file()]
    if not files:
        return BackupFreshness(backup_dir=backup_dir, newest_file=None, age_days=None, is_stale=True)
    newest = max(files, key=lambda item: item.stat().st_mtime)
    age_days = (time.time() - newest.stat().st_mtime) / 86400
    return BackupFreshness(
        backup_dir=backup_dir,
        newest_file=str(newest),
        age_days=round(age_days, 1),
        is_stale=age_days > max_age_days,
    )


def summarize_access_log_spikes(log_path: str, top_n: int = 10) -> tuple[tuple[str, int], ...]:
    """Count requests per source IP in a combined-format access log and
    return the top N IPs by request count, for a human to eyeball for
    scripted/abusive traffic.
    """
    path = Path(log_path)
    if not path.exists():
        raise ValueError(f"log file does not exist: {log_path}")
    counts: Counter[str] = Counter()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _ACCESS_LOG_IP_RE.match(line)
            if match:
                counts[match.group(1)] += 1
    return tuple(counts.most_common(top_n))


def check_rogue_admins(
    db_config: DBConfig, known_admin_logins: tuple[str, ...]
) -> tuple[RogueAdmin, ...]:
    """Re-exported for convenience so the monthly script has one import."""
    return find_rogue_admin_accounts(db_config, known_admin_logins)


MANUAL_CHECKLIST_ITEMS = (
    "Confirm 2FA is still enabled on every admin account (not automatable from outside WordPress).",
    "Spot-check Stripe webhook logs for source IPs outside Stripe's published ranges.",
    "Re-run the IDOR two-account test on any endpoints added this month (see recon/idor_tester.py).",
)
