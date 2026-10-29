"""Cashfree Payment Gateway helpers (server-side only).

Follows Cashfree hosted web checkout:
https://www.cashfree.com/docs/payments/online/web/redirect
"""
from __future__ import annotations

import base64
import hmac
import logging
import re
from typing import Any

import requests

from ..config import Config
from ..utils import ApiError

log = logging.getLogger("watchfront.cashfree")

# Modes Cashfree accepts in order_meta.payment_methods (comma-separated).
# Leave blank via env to show every method enabled on the merchant account.
DEFAULT_PAYMENT_METHODS = "cc,dc,upi,nb,app,paylater"


def enabled() -> bool:
    return bool(Config.CASHFREE_APP_ID and Config.CASHFREE_SECRET_KEY)


def mode() -> str:
    return "sandbox" if Config.CASHFREE_ENV == "sandbox" else "production"


def base_url() -> str:
    return "https://sandbox.cashfree.com/pg" if mode() == "sandbox" else "https://api.cashfree.com/pg"


def payment_methods() -> str:
    raw = (Config.CASHFREE_PAYMENT_METHODS or DEFAULT_PAYMENT_METHODS).strip()
    # Normalise: lowercase, no spaces
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    return ",".join(parts)


def normalize_phone(raw: str | None) -> str:
    """Cashfree expects a 10-digit Indian mobile for domestic PG (no +91 prefix)."""
    digits = re.sub(r"\D", "", str(raw or ""))
    if digits.startswith("91") and len(digits) >= 12:
        digits = digits[-10:]
    elif len(digits) > 10:
        digits = digits[-10:]
    return digits


def _headers() -> dict[str, str]:
    if not enabled():
        raise ApiError("Cashfree is not configured", 503, "billing_unavailable")
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-client-id": Config.CASHFREE_APP_ID,
        "x-client-secret": Config.CASHFREE_SECRET_KEY,
        "x-api-version": Config.CASHFREE_API_VERSION,
    }


def create_order(
    *,
    order_id: str,
    amount_inr: float,
    customer_id: str,
    customer_email: str,
    customer_phone: str,
    customer_name: str,
    return_url: str,
    notify_url: str,
    order_note: str = "",
    tags: dict[str, str] | None = None,
    methods: str | None = None,
) -> dict[str, Any]:
    phone = normalize_phone(customer_phone)
    if len(phone) != 10 or phone[0] not in "6789":
        raise ApiError(
            "Enter a valid 10-digit Indian mobile number for checkout (required by Cashfree).",
            422,
            "invalid_phone",
        )

    if mode() == "production":
        if not notify_url.startswith("https://"):
            raise ApiError("PUBLIC_API_URL must be https for Cashfree notify_url in production", 500)
        if not return_url.startswith("https://"):
            raise ApiError("APP_URL must be https for Cashfree return_url in production", 500)

    methods_csv = (methods if methods is not None else payment_methods()).strip()

    order_meta: dict[str, Any] = {
        # Cashfree replaces {order_id} when redirecting back from bank/UPI pages.
        "return_url": return_url,
        "notify_url": notify_url,
    }
    if methods_csv:
        order_meta["payment_methods"] = methods_csv

    payload: dict[str, Any] = {
        "order_id": order_id,
        "order_amount": round(float(amount_inr), 2),
        "order_currency": "INR",
        "customer_details": {
            "customer_id": str(customer_id)[:50],
            "customer_email": (customer_email or "billing@watchfront.in")[:100],
            "customer_phone": phone,
            "customer_name": (customer_name or "Customer")[:100],
        },
        "order_meta": order_meta,
        "order_note": (order_note or "Watchfront subscription")[:200],
        "order_tags": {str(k)[:32]: str(v)[:128] for k, v in (tags or {}).items()},
    }

    r = requests.post(f"{base_url()}/orders", json=payload, headers=_headers(), timeout=30)
    if r.status_code >= 400:
        log.warning("cashfree create_order failed: %s %s", r.status_code, r.text[:800])
        try:
            body = r.json()
            detail = body.get("message") or body.get("error") or r.text
            code = body.get("code") or body.get("type") or ""
        except Exception:  # noqa: BLE001
            detail, code = r.text, ""
        msg = str(detail).strip() or f"HTTP {r.status_code}"
        cf_code = str(code or "").strip() or f"http_{r.status_code}"
        low = msg.lower()
        # Map common Cashfree failures to clear UI codes + messages
        if "transaction" in low and "not enabled" in low:
            raise ApiError(
                "Cashfree production transactions are not enabled yet. "
                "Complete KYC / activate Payment Gateway in the Cashfree dashboard, then retry.",
                502,
                "cashfree_transactions_disabled",
                extra={"provider": "cashfree", "provider_code": cf_code, "provider_message": msg},
            )
        if "whitelist" in low or ("domain" in low and ("not" in low or "invalid" in low)):
            raise ApiError(
                "Your website domain is not whitelisted with Cashfree. "
                "Add https://www.watchfront.in in Cashfree → Developers → Whitelisting.",
                502,
                "cashfree_domain_not_whitelisted",
                extra={"provider": "cashfree", "provider_code": cf_code, "provider_message": msg},
            )
        if "authentication" in low or "unauthorized" in low or r.status_code in (401, 403):
            raise ApiError(
                "Cashfree API keys were rejected. Check CASHFREE_APP_ID / CASHFREE_SECRET_KEY on Railway.",
                502,
                "cashfree_auth_failed",
                extra={"provider": "cashfree", "provider_code": cf_code, "provider_message": msg},
            )
        if "customer_phone" in low or "phone" in low:
            raise ApiError(
                "Cashfree rejected the mobile number. Use a valid 10-digit Indian mobile.",
                422,
                "cashfree_invalid_phone",
                extra={"provider": "cashfree", "provider_code": cf_code, "provider_message": msg},
            )
        raise ApiError(
            f"Payment could not be started: {msg}",
            502,
            "cashfree_order_failed",
            extra={"provider": "cashfree", "provider_code": cf_code, "provider_message": msg},
        )
    return r.json()



def get_order(order_id: str) -> dict[str, Any]:
    r = requests.get(f"{base_url()}/orders/{order_id}", headers=_headers(), timeout=20)
    if r.status_code >= 400:
        raise ApiError(f"Could not fetch Cashfree order ({r.status_code})", 502, "cashfree_error")
    return r.json()


def get_payments(order_id: str) -> list[dict[str, Any]]:
    """Confirm payment — Step 3 of Cashfree web checkout docs."""
    r = requests.get(f"{base_url()}/orders/{order_id}/payments", headers=_headers(), timeout=20)
    if r.status_code >= 400:
        log.warning("cashfree get_payments failed: %s %s", r.status_code, r.text[:300])
        return []
    data = r.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("payments"), list):
        return data["payments"]
    return []


def order_is_paid(order: dict[str, Any], payments: list[dict[str, Any]] | None = None) -> bool:
    status = (order.get("order_status") or "").upper()
    if status in ("PAID", "ACTIVE"):
        return True
    for p in payments or []:
        if (p.get("payment_status") or "").upper() == "SUCCESS":
            return True
    return False


def verify_webhook_signature(signature: str, raw_body: str, timestamp: str) -> bool:
    if not signature or not timestamp or not Config.CASHFREE_SECRET_KEY:
        return False
    signed = f"{timestamp}{raw_body}".encode()
    digest = hmac.new(Config.CASHFREE_SECRET_KEY.encode(), signed, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)
