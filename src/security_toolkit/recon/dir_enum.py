"""Phase 4.2 (security-playbook.md) directory/file brute-force — black-box
only.

`fingerprint.check_exposed_files` already checks a short, fixed list of
sensitive paths (`.git`, `.env`, backup dumps, ...) directly over HTTP;
this wraps the external `dirsearch` tool to generalize that same idea to
a much larger wordlist-based sweep, for anyone who wants deeper coverage
than the fixed list gives. Same trust model as `infra_testing.py`'s
testssl.sh/nikto wrapping — the requests themselves are made by the
external `dirsearch` process, not this toolkit's own `requests` session,
but always against the target's own scope-checked `base_url`.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from security_toolkit.config import Target
from security_toolkit.scope_guard import require_in_scope
from security_toolkit.tool_locations import resolve_dirsearch_bin

DEFAULT_EXTENSIONS = "php,env,txt,log,sql,zip,git"

# dirsearch's `--format plain` output is one "<status> <size> <url>" line
# per found path.
_FOUND_LINE = re.compile(r"^\s*\d{3}\s+\S+\s+(\S+)")


@dataclass(frozen=True)
class DirEnumResult:
    tool: str
    succeeded: bool
    flagged: bool
    found_paths: tuple[str, ...]
    detail: str


def run_dirsearch(
    target: Target,
    extensions: str = DEFAULT_EXTENSIONS,
    dirsearch_cmd: tuple[str, ...] | None = None,
    output_path: Path | None = None,
    timeout: float = 300.0,
) -> DirEnumResult:
    """Run dirsearch's wordlist-based path brute force against the
    target's base_url and flag any path it reports as found.

    `output_path` exists mainly for tests — real callers should rely on
    the default (a throwaway temp file). Parsing dirsearch's output is a
    best-effort match on its `--format plain` shape; confirm against
    your installed dirsearch version if nothing shows up but you
    expected it to.
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url in scope.json")
    require_in_scope(target.base_url, target)

    cmd = list(dirsearch_cmd) if dirsearch_cmd else list(resolve_dirsearch_bin())

    with tempfile.TemporaryDirectory() as tmp:
        resolved_output_path = output_path or (Path(tmp) / "dirsearch_output.txt")
        try:
            result = subprocess.run(
                [*cmd, "-u", target.base_url, "-e", extensions, "--format", "plain", "-o", str(resolved_output_path)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except FileNotFoundError as exc:
            return DirEnumResult(
                tool="dirsearch", succeeded=False, flagged=True, found_paths=(),
                detail=f"'dirsearch' not found; is it installed and on PATH? ({exc})",
            )
        except subprocess.TimeoutExpired:
            return DirEnumResult(
                tool="dirsearch", succeeded=False, flagged=True, found_paths=(),
                detail=f"dirsearch timed out after {timeout}s",
            )

        found_paths = ()
        if resolved_output_path.exists():
            found_paths = tuple(
                match.group(1)
                for line in resolved_output_path.read_text(encoding="utf-8").splitlines()
                if (match := _FOUND_LINE.match(line))
            )

    flagged = len(found_paths) > 0
    detail = (
        f"dirsearch found {len(found_paths)} path(s): {', '.join(found_paths)}"
        if flagged
        else "dirsearch found no additional paths beyond 404."
    )
    return DirEnumResult(tool="dirsearch", succeeded=result.returncode == 0, flagged=flagged, found_paths=found_paths, detail=detail)
