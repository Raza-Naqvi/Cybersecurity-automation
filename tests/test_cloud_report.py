from unittest.mock import MagicMock, patch

import cloudinary.uploader  # noqa: F401 — import once, unpatched, before any test mocks cloudinary.config;
# cloudinary.uploader's own module-level init calls cloudinary.config() on first import,
# which breaks if that happens while cloudinary.config is already mocked.
import pytest

from security_toolkit.reporting.cloud_report import (
    CloudinaryConfigError,
    upload_report,
    upload_report_cli,
    upload_text_file,
)
from security_toolkit.reporting.report import Finding, build_report


@pytest.fixture
def report():
    return build_report(
        title="Recon",
        target="cheerlytics",
        findings=[Finding(name="check", flagged=False, detail="ok")],
    )


@pytest.fixture
def cloudinary_env(monkeypatch):
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://key:secret@cloud")


def test_upload_report_uploads_json_and_html_and_indexes(report, cloudinary_env):
    with (
        patch("cloudinary.uploader.upload") as mock_upload,
        patch("security_toolkit.reporting.cloud_report.add_report_entry") as mock_index,
    ):
        mock_upload.side_effect = [
            {"secure_url": "https://cdn.test/recon.json"},
            {"secure_url": "https://cdn.test/recon.html"},
        ]
        result = upload_report(report)

    assert result.json_url == "https://cdn.test/recon.json"
    assert result.html_url == "https://cdn.test/recon.html"
    assert mock_upload.call_count == 2
    mock_index.assert_called_once()
    assert mock_index.call_args.kwargs["target_name"] == "cheerlytics"
    assert mock_index.call_args.kwargs["flagged"] is False


def test_upload_report_uses_raw_resource_type(report, cloudinary_env):
    with patch("cloudinary.uploader.upload") as mock_upload, patch(
        "security_toolkit.reporting.cloud_report.add_report_entry"
    ):
        mock_upload.side_effect = [{"secure_url": "u1"}, {"secure_url": "u2"}]
        upload_report(report)

    for call in mock_upload.call_args_list:
        assert call.kwargs["resource_type"] == "raw"


def test_upload_report_raises_when_no_cloudinary_config(report, monkeypatch, tmp_path):
    monkeypatch.delenv("CLOUDINARY_URL", raising=False)
    monkeypatch.delenv("CLOUDINARY_CLOUD_NAME", raising=False)
    monkeypatch.delenv("CLOUDINARY_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDINARY_API_SECRET", raising=False)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")

    with pytest.raises(CloudinaryConfigError):
        upload_report(report, dotenv_path=empty_env)


def test_upload_report_accepts_separate_credential_vars(report, monkeypatch):
    import cloudinary

    monkeypatch.delenv("CLOUDINARY_URL", raising=False)
    monkeypatch.setenv("CLOUDINARY_CLOUD_NAME", "mycloud")
    monkeypatch.setenv("CLOUDINARY_API_KEY", "key")
    monkeypatch.setenv("CLOUDINARY_API_SECRET", "secret")

    with (
        patch("cloudinary.uploader.upload") as mock_upload,
        patch("security_toolkit.reporting.cloud_report.add_report_entry"),
    ):
        mock_upload.side_effect = [{"secure_url": "u1"}, {"secure_url": "u2"}]
        upload_report(report)

    # reset_config() re-reads os.environ for real — verify the live result
    # rather than mocking cloudinary.config (which is what the bug was: a
    # mocked/stale config silently masked the real "doesn't actually
    # re-read env" problem that only showed up against a real process).
    assert cloudinary.config().cloud_name == "mycloud"
    assert cloudinary.config().api_key == "key"


def test_upload_report_cli_returns_result_on_success(report, cloudinary_env, capsys):
    with patch("cloudinary.uploader.upload") as mock_upload, patch(
        "security_toolkit.reporting.cloud_report.add_report_entry"
    ):
        mock_upload.side_effect = [{"secure_url": "u1"}, {"secure_url": "u2"}]
        result = upload_report_cli(report)

    assert result is not None
    assert "u1" in capsys.readouterr().out


def test_upload_report_cli_returns_none_and_prints_error_on_config_failure(report, monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("CLOUDINARY_URL", raising=False)
    monkeypatch.delenv("CLOUDINARY_CLOUD_NAME", raising=False)
    monkeypatch.delenv("CLOUDINARY_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDINARY_API_SECRET", raising=False)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")

    result = upload_report_cli(report, dotenv_path=empty_env)

    assert result is None
    assert "ERROR" in capsys.readouterr().err


def test_upload_text_file_uploads_and_returns_url(cloudinary_env):
    with patch("cloudinary.uploader.upload", return_value={"secure_url": "https://cdn.test/draft.md"}) as mock_upload:
        url = upload_text_file("# draft content", "cheerlytics", "findings-draft.md")

    assert url == "https://cdn.test/draft.md"
    assert mock_upload.call_args.kwargs["public_id"] == "security-toolkit/cheerlytics/findings-draft.md"
