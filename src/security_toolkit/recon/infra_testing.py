"""Phase 4.8 (security-playbook.md) infrastructure checks — black-box only.

Wraps the two external tools the playbook names for this phase rather
than reimplementing them: `testssl.sh` for TLS/certificate
misconfiguration, and `nikto` for general server misconfiguration /
outdated-software scanning. Both run entirely over the network against
the target's own public `base_url` — no filesystem, DB, or server-shell
access needed, consistent with the rest of this toolkit.

At least one of the two is required for this phase — `scripts/doctor.py`
tries to get both installed, but if only one succeeds (or was already
present), this still runs with just that one rather than skipping
entirely. Neither tool is bundled; by default this resolves them via
PATH first, then a `vendor/` copy doctor.py may have cloned in (see
`tool_locations.py`) — pass `testssl_cmd`/`nikto_cmd` explicitly to
override either.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from security_toolkit.config import Target
from security_toolkit.scope_guard import require_in_scope
from security_toolkit.tool_locations import resolve_nikto_bin, resolve_testssl_bin


@dataclass(frozen=True)
class ToolCheckResult:
    tool: str
    succeeded: bool
    flagged: bool
    detail: str


def _run_tool(args: list[str], timeout: float) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"'{args[0]}' not found; is it installed and on PATH?") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{args[0]} timed out after {timeout}s") from exc
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output


def run_testssl(target: Target, testssl_cmd: tuple[str, ...] | None = None, timeout: float = 180.0) -> ToolCheckResult:
    """Run testssl.sh against the target's base_url and flag common
    severity markers in its output (it labels findings itself as
    LOW/MEDIUM/HIGH/CRITICAL).
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url in scope.json")
    require_in_scope(target.base_url, target)

    cmd = list(testssl_cmd) if testssl_cmd else list(resolve_testssl_bin())
    try:
        succeeded, output = _run_tool([*cmd, "--quiet", "--color", "0", target.base_url], timeout)
    except RuntimeError as exc:
        return ToolCheckResult(tool="testssl.sh", succeeded=False, flagged=True, detail=str(exc))

    flagged = any(marker in output for marker in ("HIGH", "CRITICAL", "VULNERABLE", "NOT ok"))
    detail = output if flagged else "No HIGH/CRITICAL/VULNERABLE markers found in testssl.sh output."
    return ToolCheckResult(tool="testssl.sh", succeeded=succeeded, flagged=flagged, detail=detail)


def run_nikto(target: Target, nikto_cmd: tuple[str, ...] | None = None, timeout: float = 300.0) -> ToolCheckResult:
    """Run nikto against the target's base_url. Nikto reports findings as
    a flat list of lines starting with '+' — any output beyond its
    banner/summary lines is treated as something worth a human's review.
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url in scope.json")
    require_in_scope(target.base_url, target)

    cmd = list(nikto_cmd) if nikto_cmd else list(resolve_nikto_bin())
    try:
        succeeded, output = _run_tool([*cmd, "-h", target.base_url, "-ask", "no"], timeout)
    except RuntimeError as exc:
        return ToolCheckResult(tool="nikto", succeeded=False, flagged=True, detail=str(exc))

    finding_lines = [line for line in output.splitlines() if line.strip().startswith("+") and "0 host(s) tested" not in line]
    flagged = len(finding_lines) > 0
    detail = "\n".join(finding_lines) if flagged else "Nikto reported no findings."
    return ToolCheckResult(tool="nikto", succeeded=succeeded, flagged=flagged, detail=detail)
