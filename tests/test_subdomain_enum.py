import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.subdomain_enum import run_subfinder


@pytest.fixture
def target():
    return Target(
        name="staging",
        type="custom",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com/app/",
        known_admin_logins=(),
        notes="",
        auth=None,
    )


def test_run_subfinder_parses_one_per_line_output(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="api.example.com\nstaging.example.com\n", stderr="")
        result = run_subfinder(target)

    assert result.succeeded is True
    assert result.subdomains == ("api.example.com", "staging.example.com")
    assert result.flagged is False
    assert "2 subdomain" in result.detail


def test_run_subfinder_no_subdomains_not_flagged(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_subfinder(target)

    assert result.subdomains == ()
    assert result.flagged is False
    assert "No subdomains" in result.detail


def test_run_subfinder_queries_the_targets_own_hostname(target):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_subfinder(target)

    args = mock_run.call_args[0][0]
    assert "-d" in args
    assert args[args.index("-d") + 1] == "staging.example.com"


def test_run_subfinder_missing_binary_flagged(target):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_subfinder(target, subfinder_cmd=("subfinder-missing",))

    assert result.flagged is True
    assert "not found" in result.detail


def test_run_subfinder_timeout_flagged(target):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=120)):
        result = run_subfinder(target)

    assert result.flagged is True
    assert "timed out" in result.detail


def test_run_subfinder_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(RuntimeError):
        run_subfinder(target_no_url)
