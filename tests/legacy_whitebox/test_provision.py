import subprocess
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.legacy_whitebox.provision import provision_wordpress_test_user


def test_provision_wordpress_test_user_success(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Success: created user 42.", stderr="")
        result = provision_wordpress_test_user(str(tmp_path), "idor_user_a", "a@test.com")

    assert result.username == "idor_user_a"
    assert len(result.password) >= 12


def test_provision_wordpress_test_user_failure_raises(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error: user already exists.")
        with pytest.raises(RuntimeError, match="already exists"):
            provision_wordpress_test_user(str(tmp_path), "idor_user_a", "a@test.com")


def test_provision_wordpress_test_user_missing_wp_cli_raises(tmp_path):
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(RuntimeError, match="not found"):
            provision_wordpress_test_user(str(tmp_path), "idor_user_a", "a@test.com", wp_cli_bin="wp-missing")


def test_provision_wordpress_test_user_timeout_raises(tmp_path):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="wp", timeout=60)):
        with pytest.raises(RuntimeError, match="timed out"):
            provision_wordpress_test_user(str(tmp_path), "idor_user_a", "a@test.com")
