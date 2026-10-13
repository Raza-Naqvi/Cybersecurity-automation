import base64
import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.jwt_testing import (
    JwtDecodeError,
    check_alg_none_bypass,
    check_jwt_claims,
    check_rs256_to_hs256_confusion,
    check_token_storage_hint,
    check_weak_hs256_secret,
    decode_jwt,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_hs256_jwt(payload: dict, secret: str, header_extra: dict | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT", **(header_extra or {})}
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


@pytest.fixture
def target():
    return Target(
        name="staging", type="custom", environment="staging", wp_path=None,
        base_url="https://staging.example.com", known_admin_logins=(), notes="", auth=None,
    )


def test_decode_jwt_reads_header_and_payload():
    token = _make_hs256_jwt({"sub": "user1", "exp": int(time.time()) + 3600, "iss": "app", "aud": "app"}, "secret")
    decoded = decode_jwt(token)
    assert decoded.header["alg"] == "HS256"
    assert decoded.payload["sub"] == "user1"


def test_decode_jwt_rejects_malformed_token():
    with pytest.raises(JwtDecodeError):
        decode_jwt("not.a.valid.jwt.at.all")


def test_decode_jwt_rejects_non_json_segments():
    with pytest.raises(JwtDecodeError):
        decode_jwt("bm90anNvbg.bm90anNvbg.c2lnbmF0dXJl")


def test_check_jwt_claims_flags_missing_claims():
    token = _make_hs256_jwt({"sub": "user1"}, "secret")
    result = check_jwt_claims(token)
    assert result.flagged is True
    assert "exp" in result.detail


def test_check_jwt_claims_passes_when_all_present():
    token = _make_hs256_jwt({"sub": "u", "exp": 1, "iss": "a", "aud": "a"}, "secret")
    result = check_jwt_claims(token)
    assert result.flagged is False


def test_check_token_storage_hint_flags_jwt_cookie_without_httponly():
    cookie = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123; Path=/"
    result = check_token_storage_hint((cookie,), token_in_json_body=False)
    assert result.flagged is True


def test_check_token_storage_hint_not_flagged_with_httponly_cookie():
    cookie = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123; Path=/; HttpOnly"
    result = check_token_storage_hint((cookie,), token_in_json_body=False)
    assert result.flagged is False


def test_check_token_storage_hint_flags_json_body_with_no_cookie():
    result = check_token_storage_hint((), token_in_json_body=True)
    assert result.flagged is True


def test_check_alg_none_bypass_flags_accepted_forged_token(target):
    token = _make_hs256_jwt({"sub": "u", "exp": 1}, "secret")
    with patch("requests.get", return_value=MagicMock(status_code=200)) as mock_get:
        result = check_alg_none_bypass(target, "/account", token)
    assert result.flagged is True
    sent_token = mock_get.call_args.kwargs["headers"]["Authorization"].split(" ")[1]
    assert sent_token.endswith(".")  # no signature
    decoded_header = json.loads(base64.urlsafe_b64decode(sent_token.split(".")[0] + "=="))
    assert decoded_header["alg"] == "none"


def test_check_alg_none_bypass_not_flagged_when_rejected(target):
    token = _make_hs256_jwt({"sub": "u"}, "secret")
    with patch("requests.get", return_value=MagicMock(status_code=401)):
        result = check_alg_none_bypass(target, "/account", token)
    assert result.flagged is False


def test_check_weak_hs256_secret_finds_match_in_wordlist():
    token = _make_hs256_jwt({"sub": "u"}, "secret")  # "secret" is in the wordlist
    finding, matched = check_weak_hs256_secret(token)
    assert finding.flagged is True
    assert matched == "secret"


def test_check_weak_hs256_secret_no_match_for_strong_secret():
    token = _make_hs256_jwt({"sub": "u"}, "a-very-long-unguessable-random-secret-value-xyz987")
    finding, matched = check_weak_hs256_secret(token)
    assert finding.flagged is False
    assert matched is None


def test_check_weak_hs256_secret_skips_non_hs256_tokens():
    token = _make_hs256_jwt({"sub": "u"}, "secret", header_extra={"alg": "RS256"})
    finding, matched = check_weak_hs256_secret(token)
    assert finding.flagged is False
    assert matched is None
    assert "doesn't apply" in finding.detail


def test_check_rs256_to_hs256_confusion_flags_accepted_forged_token(target):
    token = _make_hs256_jwt({"sub": "u"}, "secret", header_extra={"alg": "RS256"})
    with patch("requests.get", return_value=MagicMock(status_code=200)):
        result = check_rs256_to_hs256_confusion(target, "/account", token, public_key_pem="-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----")
    assert result.flagged is True


def test_check_rs256_to_hs256_confusion_not_flagged_when_rejected(target):
    token = _make_hs256_jwt({"sub": "u"}, "secret", header_extra={"alg": "RS256"})
    with patch("requests.get", return_value=MagicMock(status_code=401)):
        result = check_rs256_to_hs256_confusion(target, "/account", token, public_key_pem="fake-key")
    assert result.flagged is False
