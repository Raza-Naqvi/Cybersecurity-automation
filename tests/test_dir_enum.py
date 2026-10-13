import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.dir_enum import run_dirsearch


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


def test_run_dirsearch_parses_found_paths(target, tmp_path):
    output_path = tmp_path / "dirsearch_out.txt"
    output_path.write_text(
        "200   1234B   https://staging.example.com/admin/\n"
        "403    512B   https://staging.example.com/.git/\n",
        encoding="utf-8",
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_dirsearch(target, output_path=output_path)

    assert result.flagged is True
    assert result.found_paths == (
        "https://staging.example.com/admin/",
        "https://staging.example.com/.git/",
    )


def test_run_dirsearch_no_paths_not_flagged(target, tmp_path):
    output_path = tmp_path / "dirsearch_out.txt"
    output_path.write_text("", encoding="utf-8")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_dirsearch(target, output_path=output_path)

    assert result.flagged is False
    assert result.found_paths == ()
    assert "no additional paths" in result.detail


def test_run_dirsearch_missing_output_file_treated_as_no_findings(target, tmp_path):
    output_path = tmp_path / "never_written.txt"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_dirsearch(target, output_path=output_path)

    assert result.flagged is False
    assert result.found_paths == ()


def test_run_dirsearch_passes_targets_base_url_and_extensions(target, tmp_path):
    output_path = tmp_path / "out.txt"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_dirsearch(target, extensions="php,env", output_path=output_path)

    args = mock_run.call_args[0][0]
    assert "-u" in args
    assert args[args.index("-u") + 1] == "https://staging.example.com"
    assert "-e" in args
    assert args[args.index("-e") + 1] == "php,env"
    assert "-O" in args
    assert args[args.index("-O") + 1] == "plain"
    assert "--auto-calibration" in args


def test_run_dirsearch_nonzero_exit_is_flagged_not_treated_as_clean(target, tmp_path):
    """A CLI-usage error (wrong flag, wrong version, a crash) must never
    be silently read as "dirsearch found nothing" — that would hide a
    broken invocation behind a false all-clear.
    """
    output_path = tmp_path / "never_written.txt"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="dirsearch: error: no such option: --format")
        result = run_dirsearch(target, output_path=output_path)

    assert result.succeeded is False
    assert result.flagged is True
    assert result.found_paths == ()
    assert "exited with status 2" in result.detail
    assert "no such option" in result.detail


def test_run_dirsearch_missing_binary_flagged(target, tmp_path):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_dirsearch(target, dirsearch_cmd=("dirsearch-missing",), output_path=tmp_path / "out.txt")

    assert result.flagged is True
    assert "not found" in result.detail


def test_run_dirsearch_timeout_flagged(target, tmp_path):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dirsearch", timeout=300)):
        result = run_dirsearch(target, output_path=tmp_path / "out.txt")

    assert result.flagged is True
    assert "timed out" in result.detail


def test_run_dirsearch_large_result_set_truncates_and_warns(target, tmp_path):
    """A soft-404 app can make dirsearch 'find' most of its wordlist at
    once — the detail text should stay readable and warn that this
    looks like a false-positive flood, not dump every path.
    """
    output_path = tmp_path / "dirsearch_out.txt"
    lines = "\n".join(f"301    100B   https://staging.example.com/fake{i}/" for i in range(40))
    output_path.write_text(lines, encoding="utf-8")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_dirsearch(target, output_path=output_path)

    assert result.flagged is True
    assert len(result.found_paths) == 40
    assert "+10 more" in result.detail
    assert "false-positive flood" in result.detail


def test_run_dirsearch_small_result_set_has_no_false_positive_warning(target, tmp_path):
    output_path = tmp_path / "dirsearch_out.txt"
    output_path.write_text("200   1234B   https://staging.example.com/admin/\n", encoding="utf-8")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_dirsearch(target, output_path=output_path)

    assert result.flagged is True
    assert "false-positive flood" not in result.detail


def test_run_dirsearch_rejects_target_without_base_url():
    target_no_url = Target(
        name="x", type="custom", environment="staging", wp_path=None, base_url=None,
        known_admin_logins=(), notes="", auth=None,
    )
    with pytest.raises(RuntimeError):
        run_dirsearch(target_no_url)
