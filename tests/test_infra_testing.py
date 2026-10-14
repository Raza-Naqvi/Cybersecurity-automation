import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.infra_testing import run_nikto, run_nuclei, run_testssl


@pytest.fixture
def target():
    return Target(
        name="staging",
        type="custom",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com",
        known_admin_logins=(),
        notes="",
        auth=None,
    )


def test_run_testssl_flags_critical_marker(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Overall Grade CRITICAL weak cipher", stderr="")
        result = run_testssl(target)

    assert result.flagged is True


def test_run_testssl_clean_output_not_flagged(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Overall Grade A+, all checks passed ok", stderr="")
        result = run_testssl(target)

    assert result.flagged is False


def test_run_testssl_missing_binary_raises_result_flagged(target):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_testssl(target, testssl_cmd=("testssl-missing",))

    assert result.flagged is True
    assert "not found" in result.detail


def test_run_testssl_timeout_flagged(target):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="testssl.sh", timeout=180)):
        result = run_testssl(target)

    assert result.flagged is True
    assert "timed out" in result.detail


def test_run_testssl_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(RuntimeError):
        run_testssl(target_no_url)


def test_run_nikto_flags_finding_lines(target):
    nikto_output = (
        "- Nikto v2.5.0\n"
        "+ Target IP: 1.2.3.4\n"
        "+ Server: nginx\n"
        "+ /admin/: Admin login page found\n"
        "+ 1 host(s) tested\n"
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=nikto_output, stderr="")
        result = run_nikto(target)

    assert result.flagged is True
    assert "Admin login page found" in result.detail


def test_run_nikto_no_findings_not_flagged(target):
    nikto_output = "- Nikto v2.5.0\n+ 0 host(s) tested\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=nikto_output, stderr="")
        result = run_nikto(target)

    assert result.flagged is False


def test_run_nikto_missing_binary_raises_result_flagged(target):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_nikto(target, nikto_cmd=("nikto-missing",))

    assert result.flagged is True
    assert "not found" in result.detail


def test_run_nikto_passes_maxtime_under_the_outer_timeout(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="- Nikto v2.5.0\n+ 0 host(s) tested\n", stderr="")
        run_nikto(target, timeout=300.0)

    args = mock_run.call_args[0][0]
    assert "-maxtime" in args
    assert args[args.index("-maxtime") + 1] == "290s"


def _jsonl(*records: dict) -> str:
    return "\n".join(json.dumps(r) for r in records)


def test_run_nuclei_flags_non_info_severity(target):
    output = _jsonl(
        {"template-id": "exposed-panel", "info": {"severity": "high"}, "matched-at": "https://staging.example.com/admin"},
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        result = run_nuclei(target)

    assert result.flagged is True
    assert "exposed-panel" in result.detail
    assert "high" in result.detail


def test_run_nuclei_info_severity_only_not_flagged(target):
    output = _jsonl(
        {"template-id": "tech-detect", "info": {"severity": "info"}, "matched-at": "https://staging.example.com/"},
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        result = run_nuclei(target)

    assert result.flagged is False
    assert "info-level" in result.detail


def test_run_nuclei_no_matches_not_flagged(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_nuclei(target)

    assert result.flagged is False
    assert "No findings" in result.detail


def test_run_nuclei_ignores_unparseable_lines(target):
    output = "this is not json\n" + _jsonl(
        {"template-id": "x", "info": {"severity": "medium"}, "matched-at": "https://staging.example.com/x"}
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        result = run_nuclei(target)

    assert result.flagged is True
    assert "x" in result.detail


def test_run_nuclei_passes_scoped_url_and_jsonl_flag(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_nuclei(target)

    args = mock_run.call_args[0][0]
    assert "-u" in args
    assert args[args.index("-u") + 1] == "https://staging.example.com"
    assert "-jsonl" in args
    assert "-silent" in args


def test_run_nuclei_nonzero_exit_is_flagged_not_treated_as_clean(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="nuclei: error: unknown flag")
        result = run_nuclei(target)

    assert result.succeeded is False
    assert result.flagged is True
    assert "exited with status 1" in result.detail
    assert "unknown flag" in result.detail


def test_run_nuclei_missing_binary_flagged(target):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_nuclei(target, nuclei_cmd=("nuclei-missing",))

    assert result.flagged is True
    assert "not found" in result.detail


def test_run_nuclei_timeout_flagged(target):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=300)):
        result = run_nuclei(target)

    assert result.flagged is True
    assert "timed out" in result.detail


def test_run_nuclei_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(RuntimeError):
        run_nuclei(target_no_url)
