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

import json
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


@dataclass(frozen=True)
class BusinessLogicCases:
    price_tamper: tuple[PriceTamperCase, ...] = ()
    coupon_reuse: tuple[CouponReuseCase, ...] = ()
    rate_limited_action: tuple[RateLimitedActionCase, ...] = ()
    webhook_forgery: tuple[WebhookForgeryCase, ...] = ()


def load_business_logic_cases(path: str) -> BusinessLogicCases:
    """Load every case type from a JSON file shaped like
    `config/business_logic_cases.example.json` — kept next to the
    dataclasses it builds, same pattern as
    `injection_testing.load_injection_points`.
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return BusinessLogicCases(
        price_tamper=tuple(
            PriceTamperCase(
                name=item["name"],
                path=item["path"],
                method=item.get("method", "post"),
                param_name=item.get("param_name", "price"),
                param_location=item.get("param_location", "json"),
                tampered_value=item.get("tampered_value", 0.01),
                extra_params=item.get("extra_params", {}),
            )
            for item in data.get("price_tamper_cases", [])
        ),
        coupon_reuse=tuple(
            CouponReuseCase(
                name=item["name"],
                path=item["path"],
                code=item["code"],
                method=item.get("method", "post"),
                param_name=item.get("param_name", "coupon_code"),
                param_location=item.get("param_location", "json"),
                extra_params=item.get("extra_params", {}),
                max_allowed_uses=item.get("max_allowed_uses", 1),
            )
            for item in data.get("coupon_reuse_cases", [])
        ),
        rate_limited_action=tuple(
            RateLimitedActionCase(
                name=item["name"],
                path=item["path"],
                method=item.get("method", "post"),
                payload=item.get("payload", {}),
                param_location=item.get("param_location", "json"),
            )
            for item in data.get("rate_limited_action_cases", [])
        ),
        webhook_forgery=tuple(
            WebhookForgeryCase(
                name=item["name"],
                path=item["path"],
                payload=item["payload"],
                bogus_signature_header=item.get("bogus_signature_header"),
                bogus_signature_value=item.get("bogus_signature_value", "t=0,v1=deadbeef"),
            )
            for item in data.get("webhook_forgery_cases", [])
        ),
    )


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


def _accepted_detail(prefix: str, response: requests.Response, accepted_note: str) -> tuple[bool, str]:
    """`(accepted, detail)` for the common "send once, flag on 2xx" shape
    shared by price tampering and forged-webhook checks.
    """
    accepted = 200 <= response.status_code < 300
    detail = f"status={response.status_code}; {prefix} was " + (
        f"ACCEPTED — {accepted_note}" if accepted else "rejected, as expected."
    )
    return accepted, detail


def check_price_tampering(
    target: Target, case: PriceTamperCase, session: requests.Session | None = None, timeout: float = 10.0
) -> BusinessLogicFinding:
    body = {**case.extra_params, case.param_name: case.tampered_value}
    response = _send(target, case.path, case.method, body, case.param_location, session, timeout)
    accepted, detail = _accepted_detail(
        f"tampered {case.param_name}={case.tampered_value!r}",
        response,
        "confirm the server recomputes this value itself rather than trusting the request.",
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

    signature_note = "a bogus signature header" if case.bogus_signature_header else "no signature header"
    accepted, detail = _accepted_detail(
        f"forged event with {signature_note}",
        response,
        "the endpoint may not be verifying signatures. Confirm it didn't also apply a real side effect.",
    )
    return BusinessLogicFinding(case_name=case.name, check="forged_webhook", flagged=accepted, detail=detail)
