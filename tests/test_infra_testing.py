import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.infra_testing import run_nikto, run_testssl


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
        result = run_testssl(target, testssl_bin="testssl-missing")

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
        result = run_nikto(target, nikto_bin="nikto-missing")

    assert result.flagged is True
    assert "not found" in result.detail
