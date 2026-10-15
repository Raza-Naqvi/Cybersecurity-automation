"""Phase 4.8 (security-playbook.md) infrastructure checks — black-box only.

Wraps three external tools rather than reimplementing them: `testssl.sh`
for TLS/certificate misconfiguration, `nikto` for general server
misconfiguration/outdated-software scanning (both named by the
playbook for this phase), and `nuclei` for broad CVE-template-based
scanning (playbook names it for Phase 4.2's general scanner sweep, but
it's wired in here alongside the other two external-tool wrappers since
it's the same subprocess-wrapping concern, not a separate module). All
three run entirely over the network against the target's own public
`base_url` — no filesystem, DB, or server-shell access needed,
consistent with the rest of this toolkit.

At least one of testssl.sh/nikto is required for this phase —
`scripts/doctor.py` tries to get both installed, but if only one
succeeds (or was already present), this still runs with just that one
rather than skipping entirely. `nuclei` is optional on top of that (see
`run_nuclei`'s own docstring). None of the three are bundled; by default
this resolves them via PATH first, then (for testssl.sh/nikto) a
`vendor/` copy doctor.py may have cloned in (see `tool_locations.py`) —
pass `testssl_cmd`/`nikto_cmd`/`nuclei_cmd` explicitly to override any
of them.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from security_toolkit.config import Target
from security_toolkit.scope_guard import require_in_scope
from security_toolkit.tool_locations import resolve_nikto_bin, resolve_nuclei_bin, resolve_testssl_bin


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
        raise RuntimeError(f"Target '{target.name}' has no base_url set")
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

    Passes nikto's own `-maxtime` so it self-bounds and returns whatever
    it found up to that point, gracefully — a site that returns the
    same non-404 status for every unmatched path (a "soft 404", see
    `dir_enum.py`'s docstring) can make nikto's own huge built-in test
    database take far longer than usual, since it has no equivalent to
    dirsearch's `--auto-calibration` to skip that pattern. `-maxtime` is
    set a little under `timeout` so nikto exits on its own terms before
    this wrapper's outer subprocess timeout would otherwise kill it and
    discard everything found so far.
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url set")
    require_in_scope(target.base_url, target)

    cmd = list(nikto_cmd) if nikto_cmd else list(resolve_nikto_bin())
    maxtime = max(int(timeout) - 10, 10)
    try:
        succeeded, output = _run_tool([*cmd, "-h", target.base_url, "-ask", "no", "-maxtime", f"{maxtime}s"], timeout)
    except RuntimeError as exc:
        return ToolCheckResult(tool="nikto", succeeded=False, flagged=True, detail=str(exc))

    finding_lines = [line for line in output.splitlines() if line.strip().startswith("+") and "0 host(s) tested" not in line]
    flagged = len(finding_lines) > 0
    detail = "\n".join(finding_lines) if flagged else "Nikto reported no findings."
    return ToolCheckResult(tool="nikto", succeeded=succeeded, flagged=flagged, detail=detail)


#: How many non-info findings to spell out in nuclei's detail before
#: summarizing the rest.
_MAX_NUCLEI_FINDINGS_IN_DETAIL = 25


def run_nuclei(target: Target, nuclei_cmd: tuple[str, ...] | None = None, timeout: float = 300.0) -> ToolCheckResult:
    """Run nuclei's template-based vulnerability scanner against the
    target's base_url and flag any match above "info" severity.

    **Signal, not a verdict** — same caveat `injection_testing.py` and
    `dir_enum.py` give their own flagged results; confirm a match
    manually before reporting it, a template's matcher can trip on an
    app with an unusual response shape.

    Uses `-jsonl` (JSON Lines) output rather than nuclei's default
    human-readable format — far more reliable to parse line-by-line
    than guessing at a plain-text column shape (see `dir_enum.py`'s
    history for why that matters: a wrong assumption there once made a
    real tool failure look like "nothing found"). `-silent` suppresses
    the banner so stdout is pure JSONL; any line that isn't valid JSON
    is skipped rather than treated as an error, since nuclei's exact
    output can include non-JSON warnings even with `-silent`.

    A non-zero exit is always flagged — never silently read as "no
    findings" — same reasoning as `dir_enum.run_dirsearch`.
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url set")
    require_in_scope(target.base_url, target)

    cmd = list(nuclei_cmd) if nuclei_cmd else list(resolve_nuclei_bin())
    try:
        result = subprocess.run(
            [*cmd, "-u", target.base_url, "-jsonl", "-silent"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        return ToolCheckResult(
            tool="nuclei", succeeded=False, flagged=True,
            detail=f"'nuclei' not found; is it installed and on PATH? ({exc})",
        )
    except subprocess.TimeoutExpired:
        return ToolCheckResult(tool="nuclei", succeeded=False, flagged=True, detail=f"nuclei timed out after {timeout}s")

    if result.returncode != 0:
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return ToolCheckResult(
            tool="nuclei", succeeded=False, flagged=True,
            detail=f"nuclei exited with status {result.returncode} — check the invocation/version:\n{output[:2000]}",
        )

    all_matches: list[tuple[str, str, str]] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        info = record.get("info") or {}
        severity = str(info.get("severity", "unknown")).lower()
        template_id = record.get("template-id") or record.get("template_id") or info.get("name") or "unknown"
        matched_at = record.get("matched-at") or record.get("host") or target.base_url
        all_matches.append((str(template_id), severity, str(matched_at)))

    actionable = [match for match in all_matches if match[1] not in ("info", "unknown")]
    flagged = len(actionable) > 0
    return ToolCheckResult(tool="nuclei", succeeded=True, flagged=flagged, detail=_build_nuclei_detail(all_matches, actionable))


def _build_nuclei_detail(all_matches: list[tuple[str, str, str]], actionable: list[tuple[str, str, str]]) -> str:
    if not actionable:
        info_count = len(all_matches)
        return f"No findings above info severity. ({info_count} info-level match(es) seen.)" if info_count else "No findings."

    shown = actionable[:_MAX_NUCLEI_FINDINGS_IN_DETAIL]
    listed = "; ".join(f"[{severity}] {template_id} @ {matched_at}" for template_id, severity, matched_at in shown)
    if len(actionable) > len(shown):
        listed += f"; ... (+{len(actionable) - len(shown)} more)"
    return (
        f"nuclei found {len(actionable)} finding(s) above info severity: {listed}. "
        "SIGNAL, NOT A VERDICT — confirm each manually before reporting."
    )
