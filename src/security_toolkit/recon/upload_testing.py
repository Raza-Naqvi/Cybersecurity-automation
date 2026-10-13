"""Phase 4.6 (security-playbook.md) file-upload testing — black-box only.

Uploads a small set of crafted files that probe the techniques the
playbook calls out by name: extension bypass (double extension, case
variation, null byte), content-type spoofing, a GIF/PHP polyglot, and a
path-traversal filename. Every payload carries a unique marker and is a
harmless `<?php echo '<marker>'; ?>` — this probes for execution, it does
not try to do anything with that execution.

Two signals, not one:
  - **accepted**: the server took the upload (2xx) despite the filename/
    content-type looking like a script, not an image.
  - **executed**: fetching the uploaded file back shows the marker
    rendered as plain output (the PHP ran) rather than the literal
    `<?php ... ?>` source sitting there unexecuted. This is the one that
    actually matters — an accepted-but-never-executed upload is a much
    smaller issue than a webshell that runs.

Confirming "executed" needs a URL for the uploaded file, which an app
either returns in its response body (set `response_url_json_path`) or
follows a predictable pattern (set `uploaded_file_url_template`, e.g.
`/wp-content/uploads/{filename}`). Without either, this only reports the
"accepted" signal and flags execution as unknown — review manually.

Every request goes through `security_toolkit.scope_guard`.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

import requests

from security_toolkit.config import Target
from security_toolkit.json_paths import lookup_dotted_path
from security_toolkit.recon.rate_limit_check import RateLimitResult, check_rate_limiting
from security_toolkit.scope_guard import resolve_in_scope_url


@dataclass(frozen=True)
class UploadTestCase:
    name: str
    upload_path: str
    method: str = "post"
    file_field_name: str = "file"
    extra_fields: dict = field(default_factory=dict)
    response_url_json_path: str | None = None  # e.g. "data.url", read from the upload response's JSON
    uploaded_file_url_template: str | None = None  # e.g. "/wp-content/uploads/{filename}"


def load_upload_cases(path: str) -> list[UploadTestCase]:
    """Load a list of `UploadTestCase`s from a JSON file shaped like
    `config/upload_cases.example.json` — kept next to the dataclass it
    builds, same pattern as `injection_testing.load_injection_points`.
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [
        UploadTestCase(
            name=item["name"],
            upload_path=item["upload_path"],
            method=item.get("method", "post"),
            file_field_name=item.get("file_field_name", "file"),
            extra_fields=item.get("extra_fields", {}),
            response_url_json_path=item.get("response_url_json_path"),
            uploaded_file_url_template=item.get("uploaded_file_url_template"),
        )
        for item in data.get("cases", [])
    ]


@dataclass(frozen=True)
class UploadPayload:
    name: str
    filename: str
    content: bytes
    content_type: str


@dataclass(frozen=True)
class UploadFinding:
    case_name: str
    payload_name: str
    filename_sent: str
    upload_status_code: int
    accepted: bool
    fetch_status_code: int | None
    executed: bool | None  # None = couldn't check (no URL available)
    flagged: bool
    detail: str


def build_upload_payloads(marker: str) -> tuple[UploadPayload, ...]:
    """A fresh, uniquely-marked payload set per run so execution checks
    can't be confused by a previous run's leftover uploaded file.
    """
    php_probe = f"<?php echo '{marker}'; ?>".encode()
    gif_polyglot = b"GIF89a;" + php_probe

    return (
        UploadPayload(name="double extension", filename=f"{marker}.php.jpg", content=php_probe, content_type="image/jpeg"),
        UploadPayload(name="case variation", filename=f"{marker}.PHP", content=php_probe, content_type="image/jpeg"),
        UploadPayload(name="null byte filename", filename=f"{marker}.php%00.jpg", content=php_probe, content_type="image/jpeg"),
        UploadPayload(name="content-type spoof", filename=f"{marker}.php", content=php_probe, content_type="image/jpeg"),
        UploadPayload(name="gif/php polyglot", filename=f"{marker}.gif", content=gif_polyglot, content_type="image/gif"),
        UploadPayload(
            name="path traversal filename", filename=f"../../{marker}.php", content=php_probe, content_type="image/jpeg"
        ),
    )


def _send_upload(
    target: Target, case: UploadTestCase, payload: UploadPayload, session: requests.Session | None, timeout: float
) -> requests.Response:
    url = resolve_in_scope_url(target, case.upload_path)
    caller = session if session is not None else requests
    request_fn = getattr(caller, case.method.lower())
    files = {case.file_field_name: (payload.filename, payload.content, payload.content_type)}
    return request_fn(url, files=files, data=case.extra_fields, timeout=timeout)


def _resolve_uploaded_file_url(
    target: Target, case: UploadTestCase, payload: UploadPayload, upload_response: requests.Response
) -> str | None:
    if case.response_url_json_path:
        try:
            body = upload_response.json()
        except ValueError:
            return None
        found = lookup_dotted_path(body, case.response_url_json_path)
        return str(found) if found else None

    if case.uploaded_file_url_template:
        return resolve_in_scope_url(target, case.uploaded_file_url_template.format(filename=payload.filename))

    return None


def _check_execution(
    target: Target,
    case: UploadTestCase,
    payload: UploadPayload,
    upload_response: requests.Response,
    marker: str,
    session: requests.Session | None,
    timeout: float,
) -> tuple[int | None, bool | None]:
    """Fetch the uploaded file back (if a URL for it is available) and
    report `(fetch_status_code, executed)` — `executed` stays None when
    there's no URL to check, since that's "unknown", not "didn't run".
    """
    file_url = _resolve_uploaded_file_url(target, case, payload, upload_response)
    if not file_url:
        return None, None

    caller = session if session is not None else requests
    try:
        fetch_response = caller.get(file_url, timeout=timeout)
    except requests.RequestException:
        return None, None

    executed = marker in fetch_response.text and "<?php" not in fetch_response.text
    return fetch_response.status_code, executed


def _upload_detail(status_code: int, accepted: bool, executed: bool | None) -> str:
    if executed:
        return "EXECUTED: fetching the uploaded file returned the marker rendered as output, not raw source."
    if not accepted:
        return f"Upload rejected (status {status_code})."
    if executed is None:
        return (
            f"Upload accepted (status {status_code}) but no URL was available to "
            "confirm execution — set response_url_json_path or uploaded_file_url_template and re-run."
        )
    return f"Upload accepted (status {status_code}) but the file did not execute when fetched."


def run_upload_test_case(
    target: Target, case: UploadTestCase, session: requests.Session | None = None, timeout: float = 10.0
) -> tuple[UploadFinding, ...]:
    marker = secrets.token_hex(6)
    findings = []

    for payload in build_upload_payloads(marker):
        upload_response = _send_upload(target, case, payload, session, timeout)
        accepted = 200 <= upload_response.status_code < 300

        fetch_status, executed = (
            _check_execution(target, case, payload, upload_response, marker, session, timeout)
            if accepted
            else (None, None)
        )

        findings.append(
            UploadFinding(
                case_name=case.name,
                payload_name=payload.name,
                filename_sent=payload.filename,
                upload_status_code=upload_response.status_code,
                accepted=accepted,
                fetch_status_code=fetch_status,
                executed=executed,
                flagged=bool(executed) or (accepted and executed is None),
                detail=_upload_detail(upload_response.status_code, accepted, executed),
            )
        )

    return tuple(findings)


def check_upload_case_rate_limiting(
    target: Target, case: UploadTestCase, session: requests.Session | None = None, max_attempts: int = 10
) -> RateLimitResult:
    """Automatic rate-limit check for an upload endpoint — repeatedly
    submits one tiny benign file, every endpoint this toolkit probes
    gets this signal.
    """
    url = resolve_in_scope_url(target, case.upload_path)
    caller = session if session is not None else requests
    request_fn = getattr(caller, case.method.lower())

    def _send() -> requests.Response:
        files = {case.file_field_name: ("ratelimittest.txt", b"rate limit probe", "text/plain")}
        return request_fn(url, files=files, data=case.extra_fields, timeout=10.0)

    return check_rate_limiting(f"{case.name} (rate limit)", _send, max_attempts=max_attempts)
