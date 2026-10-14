from unittest.mock import patch

from security_toolkit.tool_locations import (
    resolve_dirsearch_bin,
    resolve_nikto_bin,
    resolve_nuclei_bin,
    resolve_subfinder_bin,
    resolve_testssl_bin,
)


def test_resolve_testssl_bin_prefers_path():
    with patch("shutil.which", return_value="/usr/local/bin/testssl.sh"):
        assert resolve_testssl_bin() == ("/usr/local/bin/testssl.sh",)


def test_resolve_testssl_bin_falls_back_to_vendored_copy():
    with patch("shutil.which", return_value=None), patch(
        "security_toolkit.tool_locations.VENDORED_TESTSSL_PATH"
    ) as mock_path:
        mock_path.exists.return_value = True
        mock_path.__str__.return_value = "/repo/vendor/testssl.sh/testssl.sh"
        assert resolve_testssl_bin() == ("/repo/vendor/testssl.sh/testssl.sh",)


def test_resolve_testssl_bin_falls_back_to_bare_name_when_nothing_found():
    with patch("shutil.which", return_value=None), patch(
        "security_toolkit.tool_locations.VENDORED_TESTSSL_PATH"
    ) as mock_path:
        mock_path.exists.return_value = False
        assert resolve_testssl_bin() == ("testssl.sh",)


def test_resolve_nikto_bin_prefers_path():
    with patch("shutil.which", return_value="/usr/local/bin/nikto"):
        assert resolve_nikto_bin() == ("/usr/local/bin/nikto",)


def test_resolve_nikto_bin_falls_back_to_vendored_perl_script():
    def fake_which(name):
        return None if name == "nikto" else "/usr/bin/perl"

    with patch("shutil.which", side_effect=fake_which), patch(
        "security_toolkit.tool_locations.VENDORED_NIKTO_PATH"
    ) as mock_path:
        mock_path.exists.return_value = True
        mock_path.__str__.return_value = "/repo/vendor/nikto/program/nikto.pl"
        assert resolve_nikto_bin() == ("/usr/bin/perl", "/repo/vendor/nikto/program/nikto.pl")


def test_resolve_nikto_bin_falls_back_to_bare_name_without_perl():
    with patch("shutil.which", return_value=None):
        assert resolve_nikto_bin() == ("nikto",)


def test_resolve_subfinder_bin_prefers_path():
    with patch("shutil.which", return_value="/usr/local/bin/subfinder"):
        assert resolve_subfinder_bin() == ("/usr/local/bin/subfinder",)


def test_resolve_subfinder_bin_falls_back_to_bare_name_when_not_on_path():
    with patch("shutil.which", return_value=None):
        assert resolve_subfinder_bin() == ("subfinder",)


def test_resolve_dirsearch_bin_prefers_path():
    with patch("shutil.which", return_value="/usr/local/bin/dirsearch"):
        assert resolve_dirsearch_bin() == ("/usr/local/bin/dirsearch",)


def test_resolve_dirsearch_bin_falls_back_to_vendored_python_script():
    def fake_which(name):
        return None if name == "dirsearch" else "/usr/bin/python3"

    with patch("shutil.which", side_effect=fake_which), patch(
        "security_toolkit.tool_locations.VENDORED_DIRSEARCH_PATH"
    ) as mock_path:
        mock_path.exists.return_value = True
        mock_path.__str__.return_value = "/repo/vendor/dirsearch/dirsearch.py"
        assert resolve_dirsearch_bin() == ("/usr/bin/python3", "/repo/vendor/dirsearch/dirsearch.py")


def test_resolve_dirsearch_bin_falls_back_to_bare_name_without_python():
    with patch("shutil.which", return_value=None):
        assert resolve_dirsearch_bin() == ("dirsearch",)


def test_resolve_nuclei_bin_prefers_path():
    with patch("shutil.which", return_value="/usr/local/bin/nuclei"):
        assert resolve_nuclei_bin() == ("/usr/local/bin/nuclei",)


def test_resolve_nuclei_bin_falls_back_to_bare_name_when_not_on_path():
    with patch("shutil.which", return_value=None):
        assert resolve_nuclei_bin() == ("nuclei",)
