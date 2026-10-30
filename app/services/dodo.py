"""Dodo Payments helpers (checkout sessions + webhooks).

Docs: https://docs.dodopayments.com/developer-resources/checkout-session
"""
from __future__ import annotations

import logging
import re
from typing import Any

from ..config import Config
from ..utils import ApiError

log = logging.getLogger("watchfront.dodo")

# plan_id → product_id (created in Dodo test/live dashboard)
DEFAULT_PRODUCTS = {
    "starter": "",
    "agency": "",
    "agency_pro": "",
}


def enabled() -> bool:
    return bool(Config.DODO_PAYMENTS_API_KEY)


def mode() -> str:
    return "test" if Config.DODO_PAYMENTS_ENV == "test_mode" else "live"


def product_id_for_plan(plan: str) -> str:
    mapping = {
        "starter": Config.DODO_PRODUCT_STARTER,
        "agency": Config.DODO_PRODUCT_AGENCY,
        "agency_pro": Config.DODO_PRODUCT_AGENCY_PRO,
    }
    pid = (mapping.get(plan) or "").strip()
    if not pid:
        raise ApiError(
            f"Dodo product id missing for plan '{plan}'. Set DODO_PRODUCT_* on Railway.",
            503,
            "billing_misconfigured",
        )
    return pid


def _client():
    from dodopayments import DodoPayments

    kwargs: dict[str, Any] = {
        "bearer_token": Config.DODO_PAYMENTS_API_KEY,
        "environment": Config.DODO_PAYMENTS_ENV if Config.DODO_PAYMENTS_ENV in ("test_mode", "live_mode") else "test_mode",
    }
    if Config.DODO_PAYMENTS_WEBHOOK_KEY:
        kwargs["webhook_key"] = Config.DODO_PAYMENTS_WEBHOOK_KEY
    return DodoPayments(**kwargs)


def normalize_phone(raw: str | None) -> str:
    digits = re.sub(r"\D", "", str(raw or ""))
    if digits.startswith("91") and len(digits) >= 12:
        digits = digits[-10:]
    elif len(digits) > 10:
        digits = digits[-10:]
    return digits


def create_checkout(
    *,
    plan: str,
    order_id: str,
    amount_inr: int,
    customer_email: str,
    customer_name: str,
    customer_phone: str | None = None,
    return_url: str,
) -> dict:
    """Create a hosted checkout session; returns session_id + checkout_url."""
    product_id = product_id_for_plan(plan)
    customer: dict[str, Any] = {
        "email": customer_email,
        "name": (customer_name or customer_email)[:100],
    }
    phone = normalize_phone(customer_phone)
    if len(phone) == 10:
        customer["phone_number"] = f"+91{phone}"

    try:
        session = _client().checkout_sessions.create(
            product_cart=[{"product_id": product_id, "quantity": 1}],
            customer=customer,
            return_url=return_url,
            metadata={
                "order_id": order_id,
                "plan": plan,
                "amount_inr": str(int(amount_inr)),
                "provider": "dodo",
            },
        )
    except Exception as e:  # noqa: BLE001
        log.warning("dodo checkout_sessions.create failed: %s", e)
        raise ApiError(f"Could not start Dodo checkout: {str(e)[:200]}", 502, "dodo_checkout_failed") from e

    session_id = getattr(session, "session_id", None) or ""
    checkout_url = getattr(session, "checkout_url", None) or ""
    if not session_id or not checkout_url:
        raise ApiError("Dodo did not return a checkout URL", 502, "dodo_missing_session")
    return {
        "session_id": session_id,
        "checkout_url": checkout_url,
        "product_id": product_id,
        "raw": session.model_dump() if hasattr(session, "model_dump") else {},
    }


def unwrap_webhook(raw_body: bytes | str, headers: dict) -> dict:
    """Verify + parse webhook. Falls back to unsafe parse in test mode if no webhook key."""
    body = raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body).encode()
    client = _client()
    hdrs = {
        "webhook-id": headers.get("webhook-id") or headers.get("Webhook-Id") or "",
        "webhook-signature": headers.get("webhook-signature") or headers.get("Webhook-Signature") or "",
        "webhook-timestamp": headers.get("webhook-timestamp") or headers.get("Webhook-Timestamp") or "",
    }
    if Config.DODO_PAYMENTS_WEBHOOK_KEY:
        try:
            event = client.webhooks.unwrap(body, headers=hdrs)
            if hasattr(event, "model_dump"):
                return event.model_dump()
            if isinstance(event, dict):
                return event
            return {"type": getattr(event, "type", None), "data": getattr(event, "data", None)}
        except Exception as e:  # noqa: BLE001
            log.warning("dodo webhook verify failed: %s", e)
            raise ApiError("Invalid Dodo webhook signature", 401, "dodo_webhook_invalid") from e

    # No webhook key configured yet — parse only in test mode.
    if Config.DODO_PAYMENTS_ENV != "test_mode":
        raise ApiError("DODO_PAYMENTS_WEBHOOK_KEY is required in live mode", 503, "billing_misconfigured")
    import json
    try:
        return json.loads(body.decode() if isinstance(body, (bytes, bytearray)) else body)
    except Exception as e:  # noqa: BLE001
        raise ApiError("Invalid webhook JSON", 400, "dodo_webhook_invalid") from e


def payment_metadata(event: dict) -> dict:
    data = event.get("data") or {}
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    if not isinstance(data, dict):
        data = {}
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    customer = data.get("customer") if isinstance(data.get("customer"), dict) else {}
    return {
        "order_id": meta.get("order_id"),
        "plan": meta.get("plan"),
        "payment_id": data.get("payment_id") or data.get("id"),
        "status": data.get("status"),
        "amount": data.get("total_amount") or data.get("amount"),
        "customer_email": customer.get("email"),
        "raw": data,
    }
