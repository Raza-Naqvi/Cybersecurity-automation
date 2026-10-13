from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.upload_testing import (
    UploadTestCase,
    build_upload_payloads,
    check_upload_case_rate_limiting,
    run_upload_test_case,
)


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


def test_build_upload_payloads_covers_known_techniques():
    payloads = build_upload_payloads("abc123")
    names = {p.name for p in payloads}
    assert names == {
        "double extension",
        "case variation",
        "null byte filename",
        "content-type spoof",
        "gif/php polyglot",
        "path traversal filename",
    }
    assert all("abc123" in p.filename for p in payloads)


def test_build_upload_payloads_polyglot_has_gif_header_and_php():
    payloads = build_upload_payloads("abc123")
    polyglot = next(p for p in payloads if p.name == "gif/php polyglot")
    assert polyglot.content.startswith(b"GIF89a;")
    assert b"<?php" in polyglot.content


def test_run_upload_test_case_flags_executed_file(target):
    case = UploadTestCase(
        name="avatar upload",
        upload_path="/upload",
        response_url_json_path="url",
    )
    with (
        patch("security_toolkit.recon.upload_testing.secrets.token_hex", return_value="abc123"),
        patch("requests.post") as mock_post,
        patch("requests.get") as mock_get,
    ):
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {"url": "https://staging.example.com/f.php"})
        mock_get.return_value = MagicMock(status_code=200, text="abc123")  # marker reflected, no raw <?php

        results = run_upload_test_case(target, case)

    assert any(r.executed is True and r.flagged is True for r in results)


def test_run_upload_test_case_not_flagged_when_source_not_executed(target):
    case = UploadTestCase(
        name="avatar upload",
        upload_path="/upload",
        response_url_json_path="url",
    )
    with patch("requests.post") as mock_post, patch("requests.get") as mock_get:
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {"url": "https://staging.example.com/f.php"})
        # server served the raw PHP source back instead of executing it
        mock_get.return_value = MagicMock(status_code=200, text="<?php echo 'abc123'; ?>")

        results = run_upload_test_case(target, case)

    assert all(r.executed is False for r in results)
    assert all(not r.flagged for r in results)


def test_run_upload_test_case_rejected_upload_not_flagged(target):
    case = UploadTestCase(name="avatar upload", upload_path="/upload")
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=415, json=lambda: {})
        results = run_upload_test_case(target, case)

    assert all(not r.accepted for r in results)
    assert all(not r.flagged for r in results)
    assert all(r.executed is None for r in results)


def test_run_upload_test_case_accepted_without_url_flags_unknown(target):
    case = UploadTestCase(name="avatar upload", upload_path="/upload")  # no URL config at all
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {})
        results = run_upload_test_case(target, case)

    assert all(r.accepted for r in results)
    assert all(r.executed is None for r in results)
    assert all(r.flagged for r in results)  # accepted + unknown execution -> flag for manual review


def test_run_upload_test_case_uses_url_template(target):
    case = UploadTestCase(
        name="wp media",
        upload_path="/wp-json/wp/v2/media",
        uploaded_file_url_template="/wp-content/uploads/{filename}",
    )
    with patch("requests.post") as mock_post, patch("requests.get") as mock_get:
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {})
        mock_get.return_value = MagicMock(status_code=404, text="not found")
        run_upload_test_case(target, case)

    called_url = mock_get.call_args.args[0]
    assert called_url.startswith("https://staging.example.com/wp-content/uploads/")


def test_check_upload_case_rate_limiting_flags_when_no_429(target):
    case = UploadTestCase(name="avatar upload", upload_path="/upload")
    with patch("requests.post", return_value=MagicMock(status_code=201)) as mock_post:
        result = check_upload_case_rate_limiting(target, case, max_attempts=3)
    assert mock_post.call_count == 3
    assert result.flagged is True


def test_check_upload_case_rate_limiting_not_flagged_when_429_seen(target):
    case = UploadTestCase(name="avatar upload", upload_path="/upload")
    with patch("requests.post", return_value=MagicMock(status_code=429)):
        result = check_upload_case_rate_limiting(case=case, target=target, max_attempts=2)
    assert result.flagged is False
