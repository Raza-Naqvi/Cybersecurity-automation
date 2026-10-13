from unittest.mock import patch

from security_toolkit.findings_report import ConsolidatedFinding, collect_flagged_findings, render_markdown
from security_toolkit.report_index import ReportIndexEntry


def _entry(title, findings, html_url="https://cdn.test/report.html"):
    return ReportIndexEntry(
        id="id1", target_name="cheerlytics", title=title, generated_at="2026-01-01T00:00:00+00:00",
        json_url="https://cdn.test/report.json", html_url=html_url, flagged=any(f["flagged"] for f in findings),
        findings=tuple(findings),
    )


def test_collect_flagged_findings_filters_out_unflagged():
    entries = (
        _entry("Recon", [{"name": "a", "flagged": True, "detail": "bad"}, {"name": "b", "flagged": False, "detail": "ok"}]),
    )
    with patch("security_toolkit.findings_report.list_report_entries", return_value=entries):
        results = collect_flagged_findings("cheerlytics")

    assert len(results) == 1
    assert results[0].name == "a"


def test_collect_flagged_findings_combines_multiple_reports():
    entries = (
        _entry("Recon", [{"name": "a", "flagged": True, "detail": "bad"}]),
        _entry("IDOR Test", [{"name": "b", "flagged": True, "detail": "worse"}]),
    )
    with patch("security_toolkit.findings_report.list_report_entries", return_value=entries):
        results = collect_flagged_findings("cheerlytics")

    assert {r.scan_title for r in results} == {"Recon", "IDOR Test"}


def test_render_markdown_groups_by_scan_title():
    findings = (
        ConsolidatedFinding(scan_title="Recon", name="a", detail="detail-a", report_url="https://x/1"),
        ConsolidatedFinding(scan_title="IDOR Test", name="b", detail="detail-b", report_url="https://x/2"),
    )
    markdown = render_markdown("cheerlytics", findings)

    assert "## Recon" in markdown
    assert "## IDOR Test" in markdown
    assert "### a" in markdown
    assert "detail-a" in markdown
    assert "**Fix:** _(fill in)_" in markdown


def test_render_markdown_handles_no_findings():
    markdown = render_markdown("cheerlytics", ())
    assert "No flagged findings" in markdown
