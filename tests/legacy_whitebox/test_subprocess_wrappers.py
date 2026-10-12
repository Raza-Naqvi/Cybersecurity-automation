import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import ScopeError, load_db_config
from security_toolkit.legacy_whitebox.incident_triage import run_core_checksum_verify
from security_toolkit.legacy_whitebox.monthly_checklist import check_wp_updates, run_npm_audit


def test_run_core_checksum_verify_passes_on_zero_exit(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        passed, output = run_core_checksum_verify(str(tmp_path))
    assert passed is True


def test_run_core_checksum_verify_flags_on_nonzero_exit(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="checksum mismatch", stderr="")
        passed, output = run_core_checksum_verify(str(tmp_path))
    assert passed is False
    assert "mismatch" in output


def test_run_core_checksum_verify_missing_wp_cli_raises(tmp_path):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(RuntimeError, match="not found"):
            run_core_checksum_verify(str(tmp_path), wp_cli_bin="wp-does-not-exist")


def test_run_core_checksum_verify_timeout_raises(tmp_path):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="wp", timeout=120)):
        with pytest.raises(RuntimeError, match="timed out"):
            run_core_checksum_verify(str(tmp_path))


def test_check_wp_updates_reports_outdated_items(tmp_path):
    def fake_run(cmd, **kwargs):
        if "check-update" in cmd:
            stdout = json.dumps([{"version": "6.9"}])
        elif "plugin" in cmd:
            stdout = json.dumps([{"name": "woocommerce"}])
        else:
            stdout = json.dumps([])
        return MagicMock(returncode=0, stdout=stdout, stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        status = check_wp_updates(str(tmp_path))

    assert status.core_update_available is True
    assert status.outdated_plugins == ("woocommerce",)
    assert status.raw_error is None


def test_check_wp_updates_surfaces_errors_without_raising(tmp_path):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        status = check_wp_updates(str(tmp_path))
    assert status.raw_error is not None


def test_run_npm_audit_without_package_json_is_not_an_error(tmp_path):
    summary = run_npm_audit(str(tmp_path))
    assert "no package.json" in summary.raw_error


def test_run_npm_audit_parses_vulnerability_counts(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    fake_output = json.dumps({"metadata": {"vulnerabilities": {"high": 2, "low": 1}}})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=fake_output, stderr="")
        summary = run_npm_audit(str(tmp_path))
    assert summary.vulnerability_counts == {"high": 2, "low": 1}
    assert summary.raw_error is None


def test_load_db_config_raises_when_env_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("DB_HOST", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_USER", raising=False)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")
    with pytest.raises(ScopeError):
        load_db_config()


def test_load_db_config_builds_from_env(monkeypatch):
    monkeypatch.setenv("DB_HOST", "127.0.0.1")
    monkeypatch.setenv("DB_NAME", "wp")
    monkeypatch.setenv("DB_USER", "readonly")
    monkeypatch.setenv("DB_PASSWORD", "secret")
    config = load_db_config()
    assert config.host == "127.0.0.1"
    assert config.port == 3306
