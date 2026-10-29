"""Cashfree Payment Gateway helpers (server-side only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from typing import Any

import requests

from ..config import Config
from ..utils import ApiError

log = logging.getLogger("siteguard.cashfree")


def enabled() -> bool:
    return bool(Config.CASHFREE_APP_ID and Config.CASHFREE_SECRET_KEY)


def mode() -> str:
    return "sandbox" if Config.CASHFREE_ENV == "sandbox" else "production"


def base_url() -> str:
    return "https://sandbox.cashfree.com/pg" if mode() == "sandbox" else "https://api.cashfree.com/pg"


def _headers() -> dict[str, str]:
    if not enabled():
        raise ApiError("Cashfree is not configured", 503, "billing_unavailable")
    return {
        "Content-Type": "application/json",
        "x-client-id": Config.CASHFREE_APP_ID,
        "x-client-secret": Config.CASHFREE_SECRET_KEY,
        "x-api-version": Config.CASHFREE_API_VERSION,
    }


def create_order(*, order_id: str, amount_inr: float, customer_id: str, customer_email: str,
                 customer_phone: str, customer_name: str, return_url: str, notify_url: str,
                 tags: dict[str, str] | None = None) -> dict[str, Any]:
    payload = {
        "order_id": order_id,
        "order_amount": round(float(amount_inr), 2),
        "order_currency": "INR",
        "customer_details": {
            "customer_id": customer_id[:50],
            "customer_email": (customer_email or "billing@siteguard.app")[:100],
            "customer_phone": (customer_phone or "9999999999")[:15],
            "customer_name": (customer_name or "SiteGuard")[:100],
        },
        "order_meta": {
            "return_url": return_url,
            "notify_url": notify_url,
        },
        "order_tags": {str(k)[:32]: str(v)[:128] for k, v in (tags or {}).items()},
    }
    r = requests.post(f"{base_url()}/orders", json=payload, headers=_headers(), timeout=30)
    if r.status_code >= 400:
        log.warning("cashfree create_order failed: %s %s", r.status_code, r.text[:500])
        try:
            detail = r.json().get("message") or r.text
        except Exception:  # noqa: BLE001
            detail = r.text
        raise ApiError(f"Cashfree order failed: {detail}", 502, "cashfree_error")
    return r.json()


def get_order(order_id: str) -> dict[str, Any]:
    r = requests.get(f"{base_url()}/orders/{order_id}", headers=_headers(), timeout=20)
    if r.status_code >= 400:
        raise ApiError(f"Could not fetch Cashfree order ({r.status_code})", 502, "cashfree_error")
    return r.json()


def verify_webhook_signature(signature: str, raw_body: str, timestamp: str) -> bool:
    if not signature or not timestamp or not Config.CASHFREE_SECRET_KEY:
        return False
    signed = f"{timestamp}{raw_body}".encode()
    digest = hmac.new(Config.CASHFREE_SECRET_KEY.encode(), signed, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)
