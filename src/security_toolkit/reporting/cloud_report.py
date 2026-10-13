"""Upload a report straight to Cloudinary — built in memory, never
written to local disk. This is the normal workflow's report sink;
`report.write_report` (local files) is kept only for tests/back-compat.

Every upload also gets indexed in MongoDB (`report_index.py`) so a
future dashboard can list every report, from any machine, with one
query — rather than scraping Cloudinary's folder structure.

Configure via `.env`: `CLOUDINARY_URL` (the single connection string
Cloudinary's dashboard gives you — `cloudinary://<key>:<secret>@<cloud_name>`)
or the three separate `CLOUDINARY_CLOUD_NAME`/`CLOUDINARY_API_KEY`/
`CLOUDINARY_API_SECRET` vars. Reports can contain real findings about a
real site — Cloudinary account access is as sensitive as the MongoDB
credential store; never point it at a shared account.
"""

from __future__ import annotations

import io
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from security_toolkit.report_index import add_report_entry
from security_toolkit.reporting.report import Report, render_html, render_json, report_base_name


class CloudinaryConfigError(RuntimeError):
    """Raised when no Cloudinary credentials are configured."""


@dataclass(frozen=True)
class CloudReportResult:
    json_url: str
    html_url: str


def _configure_cloudinary(dotenv_path: Path | None = None) -> None:
    import cloudinary  # lazy import — only needed when actually uploading

    already_configured = os.environ.get("CLOUDINARY_URL") or all(
        os.environ.get(key) for key in ("CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET")
    )
    if not already_configured:
        # .env isn't loaded automatically anywhere else in the process.
        # `dotenv_path` exists mainly for tests, to avoid reading the real .env.
        from security_toolkit.config import load_env

        load_env(dotenv_path)

    required = ("CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET")
    if not os.environ.get("CLOUDINARY_URL") and not all(os.environ.get(key) for key in required):
        raise CloudinaryConfigError(
            f"Missing Cloudinary config: set CLOUDINARY_URL, or all of {', '.join(required)}, in .env."
        )

    # cloudinary's own Config object only auto-reads CLOUDINARY_URL/the
    # separate vars once, at `cloudinary`'s first import in the process —
    # which can happen before .env is loaded (e.g. doctor.py's package
    # check imports it with an empty environment). reset_config() forces
    # a fresh re-read of os.environ right now; config(cloudinary_url=...)
    # does NOT do this — it just sets a literal attribute, it doesn't parse.
    cloudinary.reset_config()


def _upload_raw(content: str, public_id: str) -> str:
    import cloudinary.uploader

    result = cloudinary.uploader.upload(
        io.BytesIO(content.encode("utf-8")),
        resource_type="raw",
        public_id=public_id,
        overwrite=False,
    )
    return result["secure_url"]


def upload_text_file(content: str, target_name: str, filename: str, dotenv_path: Path | None = None) -> str:
    """Upload an arbitrary text file (e.g. a consolidated findings
    Markdown draft) to the same Cloudinary folder reports use. Returns
    its URL.
    """
    _configure_cloudinary(dotenv_path)
    return _upload_raw(content, f"security-toolkit/{target_name}/{filename}")


def upload_report(
    report: Report, mongodb_uri: str | None = None, dotenv_path: Path | None = None
) -> CloudReportResult:
    """Render a report to JSON+HTML, upload both to Cloudinary, index the
    result in MongoDB, and return the two URLs. Nothing touches local disk.
    `dotenv_path` exists mainly for tests.
    """
    _configure_cloudinary(dotenv_path)
    base_name = report_base_name(report)
    folder = f"security-toolkit/{report.target}"

    json_url = _upload_raw(render_json(report), f"{folder}/{base_name}.json")
    html_url = _upload_raw(render_html(report), f"{folder}/{base_name}.html")

    add_report_entry(
        target_name=report.target,
        title=report.title,
        generated_at=report.generated_at,
        json_url=json_url,
        html_url=html_url,
        flagged=report.has_flags,
        findings=tuple(finding.__dict__ for finding in report.findings),
        uri=mongodb_uri,
    )

    return CloudReportResult(json_url=json_url, html_url=html_url)


def upload_report_cli(
    report: Report, mongodb_uri: str | None = None, dotenv_path: Path | None = None
) -> CloudReportResult | None:
    """CLI-friendly wrapper: upload the report, print the result, and
    print+swallow a `CloudinaryConfigError` instead of raising — so a
    script can just do `if upload_report_cli(report) is None: return 1`.
    """
    try:
        result = upload_report(report, mongodb_uri=mongodb_uri, dotenv_path=dotenv_path)
    except CloudinaryConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
    print(f"Report uploaded:\n  JSON: {result.json_url}\n  HTML: {result.html_url}")
    return result
