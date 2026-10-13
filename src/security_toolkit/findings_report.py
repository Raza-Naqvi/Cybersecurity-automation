"""Synthesize one consolidated findings write-up for a target, pulled
from every report already indexed in MongoDB (`report_index.py`) —
instead of you manually collecting links from each separate scan.

This automates the *aggregation* of Phase 4.10 ("document every
finding"): it groups every flagged finding by scan type, with the
reproduction detail each check already captured. It does NOT write the
"fix applied" column or decide what's worth escalating — that's still a
human judgement call, by design, before anything goes to the dev team.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from security_toolkit.report_index import list_report_entries


@dataclass(frozen=True)
class ConsolidatedFinding:
    scan_title: str
    name: str
    detail: str
    report_url: str


def collect_flagged_findings(target_name: str, uri: str | None = None) -> tuple[ConsolidatedFinding, ...]:
    """Pull every flagged finding across every report ever indexed for
    this target, newest scan of each type's findings included (not
    deduplicated across re-runs — a finding flagged in both an old and a
    new run shows up twice, which is correct: it means it's still there).
    """
    entries = list_report_entries(target_name, uri=uri)
    findings = []
    for entry in entries:
        for finding in entry.findings:
            if finding.get("flagged"):
                findings.append(
                    ConsolidatedFinding(
                        scan_title=entry.title,
                        name=finding.get("name", "(unnamed)"),
                        detail=finding.get("detail", ""),
                        report_url=entry.html_url,
                    )
                )
    return tuple(findings)


def render_markdown(target_name: str, findings: tuple[ConsolidatedFinding, ...]) -> str:
    """One Markdown write-up, grouped by scan type, ready for a human to
    read once, add fix/priority notes to, and hand to the dev team.
    """
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# Security Findings — {target_name}",
        "",
        f"Generated: {generated_at}",
        "",
        f"**{len(findings)} flagged finding(s)** across all scans run so far for this target. "
        "Each one is a signal from an automated check — confirm it manually before treating it "
        "as a verified vulnerability, then fill in the Fix column before sending this to dev.",
        "",
    ]

    if not findings:
        lines.append("No flagged findings on record for this target. ✅")
        return "\n".join(lines)

    by_scan: dict[str, list[ConsolidatedFinding]] = {}
    for finding in findings:
        by_scan.setdefault(finding.scan_title, []).append(finding)

    for scan_title, scan_findings in by_scan.items():
        lines.append(f"## {scan_title} ({len(scan_findings)})")
        lines.append("")
        for finding in scan_findings:
            lines.append(f"### {finding.name}")
            lines.append("")
            lines.append("**Detail / reproduction:**")
            lines.append("```")
            lines.append(finding.detail)
            lines.append("```")
            lines.append("")
            lines.append(f"**Full report:** {finding.report_url}")
            lines.append("")
            lines.append("**Impact:** _(fill in)_  ")
            lines.append("**Fix:** _(fill in)_")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
