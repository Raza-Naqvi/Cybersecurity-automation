from unittest.mock import patch

import pytest

from security_toolkit.doctor_checks import (
    build_git_clone_command,
    build_package_manager_install_command,
    check_cloudinary_env_keys,
    check_env_file,
    check_package_importable,
    check_python_version,
    check_safe_browsing_env_key,
    check_tool_on_path,
    detect_os,
    detect_package_manager,
    parse_env_file,
)


def test_check_python_version_passes_on_modern_python():
    result = check_python_version((3, 12, 1))
    assert result.passed is True


def test_check_python_version_fails_on_old_python():
    result = check_python_version((3, 9, 0))
    assert result.passed is False
    assert "3.9.0" in result.detail
    assert result.fix_hint is not None


def test_check_package_importable_passes_for_real_module():
    result = check_package_importable("os", "os")
    assert result.passed is True


def test_check_package_importable_fails_for_missing_module():
    result = check_package_importable("this_module_does_not_exist_xyz", "fake-pkg")
    assert result.passed is False
    assert "pip install" in result.fix_hint


def test_parse_env_file_ignores_comments_and_blank_lines():
    content = "# comment\n\nFOO=bar\nBAZ=\n"
    values = parse_env_file(content)
    assert values == {"FOO": "bar", "BAZ": ""}


def test_check_env_file_missing_file(tmp_path):
    result = check_env_file(tmp_path / "does-not-exist.env", ("MONGODB_URI",))
    assert result.passed is False
    assert "missing" in result.detail


def test_check_env_file_missing_required_key(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("SOMETHING_ELSE=1\n")
    result = check_env_file(env_path, ("MONGODB_URI",))
    assert result.passed is False
    assert "MONGODB_URI" in result.detail


def test_check_env_file_passes_when_required_key_set(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("MONGODB_URI=mongodb://localhost:27017\n")
    result = check_env_file(env_path, ("MONGODB_URI",))
    assert result.passed is True


def test_check_cloudinary_env_keys_passes_with_url():
    result = check_cloudinary_env_keys({"CLOUDINARY_URL": "cloudinary://a:b@c"})
    assert result.passed is True


def test_check_cloudinary_env_keys_passes_with_separate_vars():
    result = check_cloudinary_env_keys(
        {"CLOUDINARY_CLOUD_NAME": "x", "CLOUDINARY_API_KEY": "y", "CLOUDINARY_API_SECRET": "z"}
    )
    assert result.passed is True


def test_check_cloudinary_env_keys_fails_when_neither_set():
    result = check_cloudinary_env_keys({})
    assert result.passed is False


def test_check_safe_browsing_env_key_passes_when_set():
    result = check_safe_browsing_env_key({"GOOGLE_SAFE_BROWSING_API_KEY": "abc"})
    assert result.passed is True


def test_check_safe_browsing_env_key_fails_when_unset():
    result = check_safe_browsing_env_key({})
    assert result.passed is False
    assert result.fix_hint is not None


def test_detect_os_maps_darwin_to_mac():
    with patch("platform.system", return_value="Darwin"):
        assert detect_os() == "mac"


def test_detect_os_maps_windows():
    with patch("platform.system", return_value="Windows"):
        assert detect_os() == "windows"


def test_detect_os_defaults_to_linux():
    with patch("platform.system", return_value="Linux"):
        assert detect_os() == "linux"


def test_detect_package_manager_finds_first_available():
    with patch("shutil.which", side_effect=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None):
        assert detect_package_manager("linux") == "apt-get"


def test_detect_package_manager_returns_none_when_none_found():
    with patch("shutil.which", return_value=None):
        assert detect_package_manager("linux") is None


def test_build_package_manager_install_command_brew():
    assert build_package_manager_install_command("brew", "nikto") == ["brew", "install", "nikto"]


def test_build_package_manager_install_command_unsupported_manager_returns_none():
    assert build_package_manager_install_command("unknown-pm", "nikto") is None


def test_build_git_clone_command(tmp_path):
    cmd = build_git_clone_command("https://github.com/x/y.git", tmp_path / "y")
    assert cmd[:3] == ["git", "clone", "--depth"]
    assert cmd[-1] == str(tmp_path / "y")


def test_check_tool_on_path_found():
    with patch("shutil.which", return_value="/usr/local/bin/subfinder"):
        result = check_tool_on_path("subfinder", "subfinder", fix_hint="install it")
    assert result.passed is True
    assert result.detail == "/usr/local/bin/subfinder"


def test_check_tool_on_path_not_found():
    with patch("shutil.which", return_value=None):
        result = check_tool_on_path("subfinder", "subfinder", fix_hint="go install ...")
    assert result.passed is False
    assert result.fix_hint == "go install ..."
