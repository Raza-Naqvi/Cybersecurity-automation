"""Phase 4.2 (security-playbook.md) subdomain enumeration — black-box only.

Wraps the external `subfinder` tool (passive subdomain discovery via
public sources — DNS, certificate-transparency logs, etc.) rather than
reimplementing it, same trust model as `infra_testing.py`'s testssl.sh/
nikto wrapping: this toolkit doesn't make the discovery requests itself,
`subfinder` does, entirely against public third-party sources about the
domain name, not the target's server directly.

The domain queried is always derived from the authorized target's own
`base_url` — never a free-form string a caller could point elsewhere —
so this stays inside the same "only ever touches an authorized target"
model as every other check here. Purely informational recon output:
every discovered subdomain is a candidate worth a human (or a new scope
entry) looking at separately, not itself a flagged vulnerability.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse

from security_toolkit.config import Target
from security_toolkit.tool_locations import resolve_subfinder_bin


@dataclass(frozen=True)
class SubdomainEnumResult:
    tool: str
    succeeded: bool
    flagged: bool
    subdomains: tuple[str, ...]
    detail: str


def _domain_from_target(target: Target) -> str:
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url in scope.json")
    hostname = urlparse(target.base_url).hostname
    if not hostname:
        raise RuntimeError(f"Could not parse a hostname out of target '{target.name}'s base_url")
    return hostname


def run_subfinder(
    target: Target, subfinder_cmd: tuple[str, ...] | None = None, timeout: float = 120.0
) -> SubdomainEnumResult:
    """Passive subdomain discovery for the target's own domain.

    `-silent` makes subfinder print one discovered subdomain per line on
    stdout and nothing else — no banner/progress noise to filter out.
    """
    domain = _domain_from_target(target)
    cmd = list(subfinder_cmd) if subfinder_cmd else list(resolve_subfinder_bin())

    try:
        result = subprocess.run([*cmd, "-d", domain, "-silent"], capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return SubdomainEnumResult(
            tool="subfinder", succeeded=False, flagged=True, subdomains=(),
            detail=f"'subfinder' not found; is it installed and on PATH? ({exc})",
        )
    except subprocess.TimeoutExpired:
        return SubdomainEnumResult(
            tool="subfinder", succeeded=False, flagged=True, subdomains=(),
            detail=f"subfinder timed out after {timeout}s",
        )

    subdomains = tuple(line.strip() for line in (result.stdout or "").splitlines() if line.strip())
    detail = (
        f"Found {len(subdomains)} subdomain(s): {', '.join(subdomains)}"
        if subdomains
        else "No subdomains discovered via passive sources."
    )
    return SubdomainEnumResult(tool="subfinder", succeeded=result.returncode == 0, flagged=False, subdomains=subdomains, detail=detail)
