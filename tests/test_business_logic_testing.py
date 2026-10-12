from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.config import Target
from security_toolkit.recon.business_logic_testing import (
    CouponReuseCase,
    PriceTamperCase,
    RateLimitedActionCase,
    WebhookForgeryCase,
    check_coupon_reuse,
    check_forged_webhook,
    check_price_tampering,
    check_rate_limited_action,
)


@pytest.fixture
def target():
    return Target(
        name="staging",
        type="custom",
        environment="staging",
        wp_path=None,
        base_url="https://staging.example.com",
        known_admin_logins=(),
        notes="",
        auth=None,
    )


def test_check_price_tampering_flags_accepted_tamper(target):
    case = PriceTamperCase(name="checkout", path="/checkout", param_name="price", tampered_value=0.01)
    with patch("requests.post", return_value=MagicMock(status_code=200)):
        result = check_price_tampering(target, case)
    assert result.flagged is True


def test_check_price_tampering_not_flagged_when_rejected(target):
    case = PriceTamperCase(name="checkout", path="/checkout", param_name="price", tampered_value=0.01)
    with patch("requests.post", return_value=MagicMock(status_code=422)):
        result = check_price_tampering(target, case)
    assert result.flagged is False


def test_check_coupon_reuse_flags_when_used_more_than_allowed(target):
    case = CouponReuseCase(name="welcome", path="/apply-coupon", code="WELCOME10", max_allowed_uses=1)
    with patch("requests.post", return_value=MagicMock(status_code=200)):
        result = check_coupon_reuse(target, case, attempts=3)
    assert result.flagged is True


def test_check_coupon_reuse_not_flagged_when_limit_enforced(target):
    case = CouponReuseCase(name="welcome", path="/apply-coupon", code="WELCOME10", max_allowed_uses=1)
    responses = [MagicMock(status_code=200), MagicMock(status_code=409), MagicMock(status_code=409)]
    with patch("requests.post", side_effect=responses):
        result = check_coupon_reuse(target, case, attempts=3)
    assert result.flagged is False


def test_check_coupon_reuse_rejects_non_positive_attempts(target):
    case = CouponReuseCase(name="welcome", path="/apply-coupon", code="WELCOME10")
    with pytest.raises(ValueError):
        check_coupon_reuse(target, case, attempts=0)


def test_check_rate_limited_action_flags_when_no_429(target):
    case = RateLimitedActionCase(name="referral", path="/referrals/redeem", payload={"code": "X"})
    with patch("requests.post", return_value=MagicMock(status_code=200)):
        result = check_rate_limited_action(target, case, max_attempts=5)
    assert result.flagged is True
    assert len(result.detail) > 0


def test_check_rate_limited_action_not_flagged_when_429_seen(target):
    case = RateLimitedActionCase(name="referral", path="/referrals/redeem", payload={"code": "X"})
    responses = [MagicMock(status_code=200)] * 3 + [MagicMock(status_code=429)] * 2
    with patch("requests.post", side_effect=responses):
        result = check_rate_limited_action(target, case, max_attempts=5)
    assert result.flagged is False


def test_check_rate_limited_action_rejects_non_positive_attempts(target):
    case = RateLimitedActionCase(name="referral", path="/referrals/redeem")
    with pytest.raises(ValueError):
        check_rate_limited_action(target, case, max_attempts=0)


def test_check_forged_webhook_flags_accepted_event(target):
    case = WebhookForgeryCase(
        name="stripe forge", path="/webhooks/stripe", payload={"type": "payment_intent.succeeded"},
        bogus_signature_header="Stripe-Signature",
    )
    with patch("requests.post", return_value=MagicMock(status_code=200)) as mock_post:
        result = check_forged_webhook(target, case)
    assert result.flagged is True
    assert mock_post.call_args.kwargs["headers"]["Stripe-Signature"] == "t=0,v1=deadbeef"


def test_check_forged_webhook_not_flagged_when_rejected(target):
    case = WebhookForgeryCase(name="stripe forge", path="/webhooks/stripe", payload={"type": "x"})
    with patch("requests.post", return_value=MagicMock(status_code=400)):
        result = check_forged_webhook(target, case)
    assert result.flagged is False
