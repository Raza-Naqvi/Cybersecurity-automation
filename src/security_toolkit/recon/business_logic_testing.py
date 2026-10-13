"""Phase 4.7 (security-playbook.md) business-logic testing — black-box
only. Scanners can't find these; they need a human (or this toolkit) to
try the specific thing the app's logic should reject.

Four checks, each config-driven so a new target is new config, not new
code:

  - **price/quantity tampering**: send a client-controlled price or
    quantity the server should recompute itself, flag if it's accepted.
  - **coupon/discount reuse**: apply the same code more times than its
    stated limit, flag if more than that many succeed.
  - **rate-limited one-time actions**: hit a referral/OTP/free-trial
    endpoint repeatedly, flag if nothing throttles it (same idea as
    `session_testing.check_login_rate_limiting`, generalized to any
    endpoint, not just login).
  - **forged webhook events**: POST a fabricated event with no valid
    signature, flag if it's accepted as real — the specific Stripe
    scenario the playbook calls out by name (Phase 2, item 7), tested
    generically here for any webhook endpoint.

Every request goes through `security_toolkit.scope_guard`. None of this
guesses at logic for you — each case has to be learned from using the
app normally first (what does a checkout response look like, what's
the coupon's real limit) and encoded into the case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests

from security_toolkit.config import Target
from security_toolkit.recon.rate_limit_check import check_rate_limiting as _check_rate_limiting
from security_toolkit.scope_guard import resolve_in_scope_url


@dataclass(frozen=True)
class BusinessLogicFinding:
    case_name: str
    check: str  # "price_tamper" | "coupon_reuse" | "rate_limit" | "forged_webhook"
    flagged: bool
    detail: str


@dataclass(frozen=True)
class PriceTamperCase:
    name: str
    path: str
    method: str = "post"
    param_name: str = "price"
    param_location: str = "json"  # "json" | "form"
    tampered_value: Any = 0.01
    extra_params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CouponReuseCase:
    name: str
    path: str
    code: str
    method: str = "post"
    param_name: str = "coupon_code"
    param_location: str = "json"
    extra_params: dict = field(default_factory=dict)
    max_allowed_uses: int = 1


@dataclass(frozen=True)
class RateLimitedActionCase:
    name: str
    path: str
    method: str = "post"
    payload: dict = field(default_factory=dict)
    param_location: str = "json"


@dataclass(frozen=True)
class WebhookForgeryCase:
    name: str
    path: str
    payload: dict
    bogus_signature_header: str | None = None  # e.g. "Stripe-Signature"
    bogus_signature_value: str = "t=0,v1=deadbeef"


def _send(
    target: Target,
    path: str,
    method: str,
    body: dict,
    param_location: str,
    session: requests.Session | None,
    timeout: float,
    headers: dict | None = None,
) -> requests.Response:
    url = resolve_in_scope_url(target, path)
    caller = session if session is not None else requests
    request_fn = getattr(caller, method.lower())
    kwargs: dict = {"timeout": timeout}
    if headers:
        kwargs["headers"] = headers
    if param_location == "json":
        kwargs["json"] = body
    elif param_location == "form":
        kwargs["data"] = body
    else:
        raise ValueError(f"Unknown param_location '{param_location}' (expected json/form)")
    return request_fn(url, **kwargs)


def check_price_tampering(
    target: Target, case: PriceTamperCase, session: requests.Session | None = None, timeout: float = 10.0
) -> BusinessLogicFinding:
    body = {**case.extra_params, case.param_name: case.tampered_value}
    response = _send(target, case.path, case.method, body, case.param_location, session, timeout)
    accepted = 200 <= response.status_code < 300
    detail = (
        f"status={response.status_code}; tampered {case.param_name}={case.tampered_value!r} was "
        + (
            "ACCEPTED — confirm the server recomputes this value itself rather than trusting the request."
            if accepted
            else "rejected, as expected."
        )
    )
    return BusinessLogicFinding(case_name=case.name, check="price_tamper", flagged=accepted, detail=detail)


def check_coupon_reuse(
    target: Target,
    case: CouponReuseCase,
    attempts: int | None = None,
    session: requests.Session | None = None,
    timeout: float = 10.0,
) -> BusinessLogicFinding:
    attempt_count = attempts if attempts is not None else case.max_allowed_uses + 2
    if attempt_count <= 0:
        raise ValueError("attempts must be a positive integer")

    status_codes = []
    successes = 0
    for _ in range(attempt_count):
        body = {**case.extra_params, case.param_name: case.code}
        response = _send(target, case.path, case.method, body, case.param_location, session, timeout)
        status_codes.append(response.status_code)
        if 200 <= response.status_code < 300:
            successes += 1

    flagged = successes > case.max_allowed_uses
    detail = (
        f"{attempt_count} attempts, {successes} succeeded (max allowed: {case.max_allowed_uses}), "
        f"status codes: {tuple(status_codes)}."
    )
    return BusinessLogicFinding(case_name=case.name, check="coupon_reuse", flagged=flagged, detail=detail)


def check_rate_limited_action(
    target: Target,
    case: RateLimitedActionCase,
    max_attempts: int = 10,
    session: requests.Session | None = None,
    timeout: float = 10.0,
) -> BusinessLogicFinding:
    """Thin wrapper around `rate_limit_check.check_rate_limiting`."""
    shared = _check_rate_limiting(
        case.name,
        lambda: _send(target, case.path, case.method, case.payload, case.param_location, session, timeout),
        max_attempts=max_attempts,
    )
    return BusinessLogicFinding(case_name=case.name, check="rate_limit", flagged=shared.flagged, detail=shared.detail)


def check_forged_webhook(target: Target, case: WebhookForgeryCase, timeout: float = 10.0) -> BusinessLogicFinding:
    headers = {case.bogus_signature_header: case.bogus_signature_value} if case.bogus_signature_header else None
    response = _send(target, case.path, "post", case.payload, "json", None, timeout, headers=headers)

    accepted = 200 <= response.status_code < 300
    detail = (
        f"status={response.status_code}; forged event with "
        f"{'a bogus signature header' if case.bogus_signature_header else 'no signature header'} was "
        + (
            "ACCEPTED — the endpoint may not be verifying signatures. Confirm it didn't also apply a real side effect."
            if accepted
            else "rejected, as expected."
        )
    )
    return BusinessLogicFinding(case_name=case.name, check="forged_webhook", flagged=accepted, detail=detail)
