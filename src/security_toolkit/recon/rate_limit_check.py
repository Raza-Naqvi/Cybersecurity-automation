"""Shared rate-limit probe — fire N requests at any endpoint and check
whether anything throttles them (HTTP 429). Used two ways:

  - explicitly, for a specific action worth calling out on its own
    (login, a coupon-apply endpoint — see session_testing.py /
    business_logic_testing.py)
  - automatically, as a side effect of other checks (IDOR cases,
    injection points, upload cases) — "for every endpoint we test,
    also check rate limiting" rather than requiring separate config.

Deliberately conservative: only an explicit HTTP 429 counts as "blocked".
A clean report here doesn't prove there's no lockout — only that this
specific signal wasn't seen; a CAPTCHA or a soft lockout page would need
a human to notice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import requests


@dataclass(frozen=True)
class RateLimitResult:
    label: str
    attempts: int
    status_codes: tuple[int, ...]
    blocked: bool
    flagged: bool
    detail: str


def check_rate_limiting(
    label: str,
    send_request: Callable[[], requests.Response],
    max_attempts: int = 10,
) -> RateLimitResult:
    """Call `send_request()` repeatedly and look for an HTTP 429 among the
    responses. `send_request` takes no arguments — callers close over
    whatever session/URL/payload they need (see the two convenience
    wrappers below for the common cases).
    """
    if max_attempts <= 0:
        raise ValueError("max_attempts must be a positive integer")

    status_codes = tuple(send_request().status_code for _ in range(max_attempts))
    blocked = 429 in status_codes
    flagged = not blocked
    detail = (
        f"{max_attempts} attempts, status codes seen: {status_codes}. "
        + (
            "No HTTP 429 observed — confirm manually whether a CAPTCHA/lockout kicked in another way."
            if flagged
            else "HTTP 429 observed — some throttling is in place."
        )
    )
    return RateLimitResult(
        label=label, attempts=max_attempts, status_codes=status_codes, blocked=blocked, flagged=flagged, detail=detail
    )


def check_rate_limiting_for_url(
    label: str,
    url: str,
    method: str = "get",
    session: requests.Session | None = None,
    json_body: dict | None = None,
    data_body: dict | None = None,
    query_params: dict | None = None,
    max_attempts: int = 10,
    timeout: float = 10.0,
) -> RateLimitResult:
    """Convenience wrapper: repeatedly call one URL with the same payload.
    This is what gets attached automatically to IDOR/injection/upload cases.
    """
    caller = session if session is not None else requests
    request_fn = getattr(caller, method.lower())

    def _send() -> requests.Response:
        kwargs: dict = {"timeout": timeout}
        if json_body is not None:
            kwargs["json"] = json_body
        if data_body is not None:
            kwargs["data"] = data_body
        if query_params is not None:
            kwargs["params"] = query_params
        return request_fn(url, **kwargs)

    return check_rate_limiting(label, _send, max_attempts=max_attempts)
