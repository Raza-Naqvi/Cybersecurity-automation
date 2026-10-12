import pytest

from security_toolkit.legacy_whitebox.incident_triage import (
    find_php_in_uploads,
    find_recently_modified_php,
    scan_for_webshell_signatures,
)


@pytest.fixture
def fake_wp_site(tmp_path):
    uploads = tmp_path / "wp-content" / "uploads" / "2026" / "01"
    uploads.mkdir(parents=True)
    return tmp_path, uploads


def test_find_php_in_uploads_flags_backdoor(fake_wp_site):
    wp_path, uploads = fake_wp_site
    backdoor = uploads / "image.php"
    backdoor.write_text("<?php eval(base64_decode($_POST['c'])); ?>")

    results = find_php_in_uploads(str(wp_path))

    assert str(backdoor) in results


def test_find_php_in_uploads_empty_when_no_uploads_dir(tmp_path):
    assert find_php_in_uploads(str(tmp_path)) == ()


def test_scan_for_webshell_signatures_detects_eval_base64(fake_wp_site):
    wp_path, uploads = fake_wp_site
    shell_path = uploads / "shell.php"
    shell_path.write_text("<?php eval(base64_decode($_GET['x'])); ?>")
    clean_path = uploads / "logo.php"
    clean_path.write_text("<?php // just a comment\n")

    flagged = scan_for_webshell_signatures((str(shell_path), str(clean_path)))

    flagged_paths = {f.path for f in flagged}
    assert str(shell_path) in flagged_paths
    assert str(clean_path) not in flagged_paths


def test_find_recently_modified_php_respects_window(tmp_path):
    recent = tmp_path / "recent.php"
    recent.write_text("<?php ?>")

    results = find_recently_modified_php(str(tmp_path), days=30)

    assert any(item.path == str(recent) for item in results)


def test_find_recently_modified_php_rejects_bad_path():
    with pytest.raises(ValueError):
        find_recently_modified_php("/path/that/does/not/exist", days=30)


def test_find_recently_modified_php_rejects_non_positive_days(tmp_path):
    with pytest.raises(ValueError):
        find_recently_modified_php(str(tmp_path), days=0)
