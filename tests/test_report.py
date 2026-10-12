from security_toolkit.reporting.report import Finding, build_report, write_report


def test_build_report_has_flags_when_any_finding_flagged():
    report = build_report(
        title="Test Report",
        target="staging",
        findings=[Finding(name="a", flagged=False, detail="ok"), Finding(name="b", flagged=True, detail="bad")],
    )
    assert report.has_flags is True


def test_build_report_no_flags_when_all_clean():
    report = build_report(
        title="Test Report",
        target="staging",
        findings=[Finding(name="a", flagged=False, detail="ok")],
    )
    assert report.has_flags is False


def test_write_report_creates_json_and_html(tmp_path):
    report = build_report(
        title="Test Report",
        target="staging",
        findings=[Finding(name="a", flagged=False, detail="ok")],
    )
    json_path, html_path = write_report(report, output_dir=tmp_path)

    assert json_path.exists()
    assert html_path.exists()
    assert "Test Report" in html_path.read_text()
