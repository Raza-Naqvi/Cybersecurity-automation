"""Phase 4.5 (security-playbook.md) SSRF testing — black-box, out-of-band
confirmation via webhook.site.

Blind SSRF mostly can't be confirmed from the HTTP response alone — the
server fetches your URL, but you never see what happened. The standard
pentester "alternate" for this is an out-of-band (OOB) callback: send a
parameter a unique URL on a service you control, then check whether that
service ever received a request. webhook.site was picked over something
like interactsh for this toolkit specifically because it's a plain REST
API (create a token, poll for hits) — no Go binary, no DNS/crypto
protocol to get wrong, which matters for correctness within this
project's pure-Python, dependency-light approach. Same confirmed-hit
outcome either way.

Every created token is a disposable, single-use URL — nothing reused
across runs, nothing that identifies this toolkit or the target.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests

from security_toolkit.config import Target
from security_toolkit.recon.injection_testing import InjectionPoint, _send_probe

WEBHOOK_SITE_BASE = "https://webhook.site"


class CallbackServiceError(RuntimeError):
    """Raised when webhook.site can't be reached to create/poll a token."""


@dataclass(frozen=True)
class SsrfFinding:
    point_name: str
    callback_url: str
    flagged: bool
    detail: str


def create_callback_token(timeout: float = 10.0) -> str:
    """Create a fresh, disposable webhook.site token. Returns its id."""
    try:
        response = requests.post(f"{WEBHOOK_SITE_BASE}/token", json={}, timeout=timeout)
        response.raise_for_status()
        return response.json()["uuid"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        raise CallbackServiceError(f"Could not create a webhook.site token: {exc}") from exc


def callback_url(token_id: str) -> str:
    return f"{WEBHOOK_SITE_BASE}/{token_id}"


def poll_for_hit(token_id: str, max_wait: float = 20.0, poll_interval: float = 2.0, timeout: float = 10.0) -> bool:
    """Poll webhook.site for any request received on this token. A hit
    means something (the target's server, if the payload triggered a
    real server-side fetch) made an outbound HTTP request to our URL.
    """
    deadline = time.time() + max_wait
    while time.time() <= deadline:
        try:
            response = requests.get(f"{WEBHOOK_SITE_BASE}/token/{token_id}/requests", timeout=timeout)
            response.raise_for_status()
            if response.json().get("data"):
                return True
        except (requests.RequestException, ValueError):
            pass  # a transient polling failure isn't a verdict either way — keep trying until the deadline
        if time.time() + poll_interval <= deadline:
            time.sleep(poll_interval)
        else:
            break
    return False


def check_ssrf(
    target: Target,
    point: InjectionPoint,
    session: requests.Session | None = None,
    max_wait: float = 20.0,
    timeout: float = 10.0,
) -> SsrfFinding:
    """Send a fresh OOB callback URL as the parameter's value, then poll
    for a hit. Flags if the target's server actually reached out to it —
    a confirmed SSRF, not just a guess from response timing/content.
    """
    token_id = create_callback_token(timeout=timeout)
    payload_url = callback_url(token_id)

    response = _send_probe(target, point, payload_url, session=session, timeout=timeout)
    hit = poll_for_hit(token_id, max_wait=max_wait, timeout=timeout)

    detail = (
        f"status={response.status_code}; FLAGGED: the target's server made an outbound request to our "
        f"callback URL ({payload_url}) — confirmed SSRF."
        if hit
        else f"status={response.status_code}; no callback received within {max_wait}s. Doesn't rule out SSRF "
        "with delayed/async processing — re-check manually if that's likely for this endpoint."
    )
    return SsrfFinding(point_name=point.name, callback_url=payload_url, flagged=hit, detail=detail)
