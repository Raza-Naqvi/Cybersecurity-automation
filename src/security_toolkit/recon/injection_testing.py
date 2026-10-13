"""Phase 4.5 (security-playbook.md) injection testing — black-box only.

Sends a small set of known-safe-to-send payloads at one named parameter
(query string, form field, or JSON body field) and looks for two kinds of
signal, neither of which needs source code:

  - **error-signature matching** (SQLi/NoSQLi): the response body contains
    a database error message that only shows up when a payload broke out
    of the query it was meant to sit inside.
  - **unescaped reflection** (XSS): a unique marker payload comes back in
    the response body byte-for-byte instead of HTML-escaped — if it does,
    a browser would render it as markup/script.

This is a signal generator for a human to confirm, not a final verdict —
a flagged SQLi finding especially should be re-checked manually (or with
`sqlmap` per the playbook's tool list) before being reported as confirmed.
Every payload here is read-only in intent (no `DROP`/`UPDATE`/`DELETE`
payloads) — this probes for a broken query, it does not try to exploit one.

Every request goes through `security_toolkit.scope_guard`.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

import requests

from security_toolkit.config import Target
from security_toolkit.recon.rate_limit_check import RateLimitResult, check_rate_limiting_for_url
from security_toolkit.scope_guard import resolve_in_scope_url

SQLI_PAYLOADS = (
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR 1=1-- -",
    "1' AND '1'='2",
    "1 AND 1=CONVERT(int, (SELECT @@version))",
)

# Error strings that only appear when a DB driver chokes on broken SQL —
# not an exhaustive list, just the common ones across engines.
SQLI_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query():",
    "sqlstate[",
    "ora-01756",
    "microsoft odbc driver",
    "sqlite3.operationalerror",
)

# NoSQL-injection-style values, meaningful only when the parameter sits in
# a JSON body (query strings/form fields can't carry a real sub-document).
NOSQLI_JSON_PAYLOADS = (
    {"$ne": None},
    {"$ne": ""},
    {"$gt": ""},
    {"$regex": ".*"},
)

NOSQLI_ERROR_SIGNATURES = (
    "mongoerror",
    "e11000 duplicate key",
    "bsonobj",
    "castError",
    "operator \"$",
)

# Each pair is (payload, expected-evaluated-output). If the output shows up
# in the response and the raw payload text doesn't, the expression most
# likely got evaluated server-side rather than just echoed back.
TEMPLATE_INJECTION_PAYLOADS = (
    ("{{7*7}}", "49"),  # Jinja2/Twig/generic mustache-style
    ("${7*7}", "49"),  # various EL/template engines
    ("<%= 7*7 %>", "49"),  # ERB
    ("#{7*7}", "49"),  # Ruby string interpolation / some EL dialects
    ("{{7*'7'}}", "7777777"),  # Jinja2-specific: distinguishes it from other engines
)


@dataclass(frozen=True)
class InjectionPoint:
    name: str
    path: str  # relative path or absolute URL, e.g. "/search"
    method: str = "get"  # "get" or "post"
    param_name: str = "q"
    param_location: str = "query"  # "query" | "form" | "json"
    extra_params: dict = field(default_factory=dict)  # other required fields, sent unchanged


def load_injection_points(path: str) -> list[InjectionPoint]:
    """Load a list of `InjectionPoint`s from a JSON file shaped like
    `config/injection_points.example.json` — shared by every CLI script
    that probes named parameters (injection, SSRF), so the file format
    only needs to be parsed in one place.
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [
        InjectionPoint(
            name=item["name"],
            path=item["path"],
            method=item.get("method", "get"),
            param_name=item.get("param_name", "q"),
            param_location=item.get("param_location", "query"),
            extra_params=item.get("extra_params", {}),
        )
        for item in data.get("points", [])
    ]


@dataclass(frozen=True)
class InjectionFinding:
    point_name: str
    category: str  # "sqli" | "nosqli" | "xss"
    payload: str
    flagged: bool
    detail: str


def _send_probe(
    target: Target,
    point: InjectionPoint,
    value,
    session: requests.Session | None = None,
    timeout: float = 10.0,
) -> requests.Response:
    url = resolve_in_scope_url(target, point.path)
    caller = session if session is not None else requests
    method = point.method.lower()
    request_fn = getattr(caller, method)

    body = {**point.extra_params, point.param_name: value}
    if point.param_location == "query":
        return request_fn(url, params=body, timeout=timeout)
    if point.param_location == "form":
        return request_fn(url, data=body, timeout=timeout)
    if point.param_location == "json":
        return request_fn(url, json=body, timeout=timeout)
    raise ValueError(f"Unknown param_location '{point.param_location}' (expected query/form/json)")


def check_sql_injection(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, timeout: float = 10.0
) -> tuple[InjectionFinding, ...]:
    findings = []
    for payload in SQLI_PAYLOADS:
        response = _send_probe(target, point, payload, session=session, timeout=timeout)
        body_lower = response.text.lower()
        matched = [sig for sig in SQLI_ERROR_SIGNATURES if sig in body_lower]
        flagged = bool(matched)
        findings.append(
            InjectionFinding(
                point_name=point.name,
                category="sqli",
                payload=payload,
                flagged=flagged,
                detail=(
                    f"status={response.status_code}; matched error signature(s): {matched}"
                    if flagged
                    else f"status={response.status_code}; no SQL error signature matched"
                ),
            )
        )
    return tuple(findings)


def check_nosql_injection(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, timeout: float = 10.0
) -> tuple[InjectionFinding, ...]:
    if point.param_location != "json":
        return (
            InjectionFinding(
                point_name=point.name,
                category="nosqli",
                payload="(skipped)",
                flagged=False,
                detail="NoSQLi operator payloads only apply to a JSON body parameter; this point uses "
                f"param_location={point.param_location!r} — skipped.",
            ),
        )

    findings = []
    for payload in NOSQLI_JSON_PAYLOADS:
        response = _send_probe(target, point, payload, session=session, timeout=timeout)
        body_lower = response.text.lower()
        error_matched = [sig for sig in NOSQLI_ERROR_SIGNATURES if sig in body_lower]
        # A 2xx on an operator payload where a plain string was expected is
        # itself a signal (common NoSQLi auth-bypass shape), on top of error text.
        suspicious_success = 200 <= response.status_code < 300
        flagged = bool(error_matched) or suspicious_success
        findings.append(
            InjectionFinding(
                point_name=point.name,
                category="nosqli",
                payload=str(payload),
                flagged=flagged,
                detail=(
                    f"status={response.status_code}; error signature(s): {error_matched}; "
                    f"operator payload accepted with a successful response — review manually, "
                    "this is the shape used for NoSQLi auth bypass"
                    if flagged
                    else f"status={response.status_code}; no error signature, no unexpected success"
                ),
            )
        )
    return tuple(findings)


def check_reflected_xss(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, timeout: float = 10.0
) -> InjectionFinding:
    marker = f"xsstest{secrets.token_hex(6)}"
    payload = f"<script>alert('{marker}')</script>"
    response = _send_probe(target, point, payload, session=session, timeout=timeout)

    reflected_unescaped = payload in response.text
    return InjectionFinding(
        point_name=point.name,
        category="xss",
        payload=payload,
        flagged=reflected_unescaped,
        detail=(
            "FLAGGED: the payload came back byte-for-byte unescaped in the response body."
            if reflected_unescaped
            else "OK: the payload was not reflected unescaped (escaped, stripped, or not reflected at all)."
        ),
    )


def check_template_injection(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, timeout: float = 10.0
) -> tuple[InjectionFinding, ...]:
    """Command/template injection (playbook 4.5): send a small expression
    in each of the common template-engine syntaxes and check if its
    evaluated result (not the literal text) comes back — that's a sign
    the expression executed server-side rather than being echoed as plain
    text.
    """
    findings = []
    for payload, expected_output in TEMPLATE_INJECTION_PAYLOADS:
        response = _send_probe(target, point, payload, session=session, timeout=timeout)
        executed = expected_output in response.text and payload not in response.text
        findings.append(
            InjectionFinding(
                point_name=point.name,
                category="template_injection",
                payload=payload,
                flagged=executed,
                detail=(
                    f"status={response.status_code}; FLAGGED: '{expected_output}' appeared in the response "
                    "and the raw payload text didn't — the expression may have evaluated server-side."
                    if executed
                    else f"status={response.status_code}; no sign of server-side evaluation"
                ),
            )
        )
    return tuple(findings)


def check_injection_point_rate_limiting(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, max_attempts: int = 10
) -> RateLimitResult:
    """Automatic rate-limit check for an injection point's endpoint —
    every endpoint this toolkit probes also gets this signal.
    """
    url = resolve_in_scope_url(target, point.path)
    baseline_value = "ratelimittest"
    body = {**point.extra_params, point.param_name: baseline_value}
    location_kwarg = {"query": "query_params", "form": "data_body", "json": "json_body"}[point.param_location]
    return check_rate_limiting_for_url(
        f"{point.name} (rate limit)",
        url,
        method=point.method,
        session=session,
        max_attempts=max_attempts,
        **{location_kwarg: body},
    )


def run_injection_suite(
    target: Target, point: InjectionPoint, session: requests.Session | None = None, timeout: float = 10.0
) -> tuple[InjectionFinding, ...]:
    """Run all four categories against one injection point."""
    return (
        *check_sql_injection(target, point, session=session, timeout=timeout),
        *check_nosql_injection(target, point, session=session, timeout=timeout),
        check_reflected_xss(target, point, session=session, timeout=timeout),
        *check_template_injection(target, point, session=session, timeout=timeout),
    )
