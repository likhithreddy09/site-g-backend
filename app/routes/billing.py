"""Cashfree hosted checkout + webhook for plan upgrades.

Flow (Cashfree web checkout docs):
1. Server creates order → payment_session_id
2. Client opens Cashfree.js checkout
3. Server confirms via webhook + GET /orders + GET /orders/{id}/payments
"""
from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..config import Config
from ..db import get_db
from ..plans import PLANS
from ..security import require
from ..services import cashfree
from ..utils import ApiError, now, ser, token
from . import body

bp = Blueprint("billing", __name__, url_prefix="/api/billing")
log = logging.getLogger("watchfront.billing")

PAID_PLANS = {"starter", "agency", "agency_pro"}


def _apply_plan(ws_id, plan: str, *, payment: dict | None = None) -> dict:
    db = get_db()
    new_limits = PLANS[plan]
    sites = db.websites.count_documents({"workspace_id": ws_id})
    if sites > new_limits["websites"]:
        raise ApiError(
            f"You have {sites} websites; the {new_limits['name']} plan allows {new_limits['websites']}. Remove some first.",
            409,
        )
    upd = {
        "plan": plan,
        "trial": False,
        "trial_ends_at": None,
        "plan_changed_at": now(),
    }
    if payment:
        prev = (db.workspaces.find_one({"_id": ws_id}, {"billing": 1}) or {}).get("billing") or {}
        upd["billing"] = {
            **prev,
            "provider": "cashfree",
            "last_order_id": payment.get("order_id"),
            "last_payment_id": payment.get("payment_id"),
            "last_paid_at": now(),
            "plan": plan,
            "amount_inr": payment.get("amount_inr"),
            "status": "active",
        }
    db.workspaces.update_one({"_id": ws_id}, {"$set": upd})
    db.websites.update_many(
        {"workspace_id": ws_id, "interval_sec": {"$lt": new_limits["min_interval_sec"]}},
        {"$set": {"interval_sec": new_limits["min_interval_sec"]}},
    )
    return db.workspaces.find_one({"_id": ws_id})


@bp.get("/config")
@require(allow_when_locked=True)
def billing_config():
    methods = cashfree.payment_methods() if cashfree.enabled() else ""
    return jsonify({
        "enabled": cashfree.enabled(),
        "mode": cashfree.mode() if cashfree.enabled() else None,
        "currency": "INR",
        "provider": "cashfree",
        "payment_methods": methods,
        "payment_methods_labels": _method_labels(methods),
        "requires_phone": True,
    })


def _method_labels(csv: str) -> list[dict]:
    labels = {
        "cc": "Credit card",
        "dc": "Debit card",
        "upi": "UPI",
        "nb": "Netbanking",
        "app": "Wallets (Paytm, PhonePe, Amazon Pay…)",
        "paylater": "Pay later",
        "ccc": "Corporate credit card",
        "ppc": "Prepaid card",
        "emi": "EMI",
        "cardlessemi": "Cardless EMI",
        "ccemi": "Credit card EMI",
        "dcemi": "Debit card EMI",
        "banktransfer": "Bank transfer",
        "applepay": "Apple Pay",
        "paypal": "PayPal",
    }
    out = []
    for m in [p.strip() for p in (csv or "").split(",") if p.strip()]:
        out.append({"id": m, "label": labels.get(m, m.upper())})
    return out


@bp.post("/checkout")
@require("owner", allow_when_locked=True)
def checkout():
    if not cashfree.enabled():
        raise ApiError(
            "Payments are not configured on this server. Set Cashfree keys on Railway.",
            503,
            "billing_unavailable",
        )
    data = body()
    plan = data.get("plan")
    if plan not in PAID_PLANS:
        raise ApiError("Choose a paid plan to checkout (Starter, Agency, or Agency Pro).", 422, "invalid_plan")
    amount = PLANS[plan]["price_inr"]
    if not amount:
        raise ApiError("This plan has no price configured.", 422, "invalid_plan_amount")

    db = get_db()
    sites = db.websites.count_documents({"workspace_id": g.ws_id})
    if sites > PLANS[plan]["websites"]:
        raise ApiError(
            f"You have {sites} websites; the {PLANS[plan]['name']} plan allows {PLANS[plan]['websites']}. Remove some first.",
            409,
        )

    user_id = g.user["_id"]
    user = db.users.find_one({"_id": user_id}) or g.user or {}
    phone_raw = data.get("phone") or user.get("phone") or ""
    phone = cashfree.normalize_phone(phone_raw)
    if len(phone) != 10 or phone[0] not in "6789":
        raise ApiError(
            "Enter a valid 10-digit Indian mobile number before paying (Cashfree requirement).",
            422,
            "invalid_phone",
        )

    # Persist phone for next checkout
    if phone != cashfree.normalize_phone(user.get("phone")):
        db.users.update_one({"_id": user_id}, {"$set": {"phone": phone}})

    order_id = f"wf_{str(g.ws_id)[-8:]}_{plan}_{token('', 8)}"
    # {order_id} placeholder is replaced by Cashfree on redirect (recommended).
    return_url = f"{Config.APP_URL}/app/billing?order_id={{order_id}}"
    notify_url = f"{Config.PUBLIC_API_URL}/api/billing/webhook"
    plan_name = PLANS[plan]["name"]

    cf_order = cashfree.create_order(
        order_id=order_id,
        amount_inr=amount,
        customer_id=str(user_id),
        customer_email=user.get("email") or "likhith.reddy@watchfront.in",
        customer_phone=phone,
        customer_name=user.get("name") or user.get("email") or "Customer",
        return_url=return_url,
        notify_url=notify_url,
        order_note=f"Watchfront {plan_name} plan monthly",
        # Cashfree: checkout_context max 100 chars, no HTML/URLs/line breaks/emojis/special symbols.
        tags={
            "plan": plan,
            "checkout_context": f"Watchfront {plan_name} plan INR {int(amount)} per month"[:100],
        },
    )

    session_id = cf_order.get("payment_session_id")
    if not session_id:
        raise ApiError("Cashfree did not return a payment_session_id", 502, "cashfree_error")

    doc = {
        "order_id": order_id,
        "cf_order_id": cf_order.get("cf_order_id") or cf_order.get("order_id"),
        "workspace_id": g.ws_id,
        "user_id": user_id,
        "plan": plan,
        "amount_inr": amount,
        "currency": "INR",
        "status": "created",
        "payment_session_id": session_id,
        "customer_phone": phone,
        "payment_methods": cashfree.payment_methods(),
        "raw_create": {k: cf_order.get(k) for k in ("cf_order_id", "order_id", "order_status", "payment_session_id") if k in cf_order},
        "created_at": now(),
        "updated_at": now(),
    }
    db.billing_orders.insert_one(doc)
    audit("billing.checkout_started", "workspace", g.ws_id, {"plan": plan, "order_id": order_id, "amount_inr": amount})

    return jsonify({
        "order_id": order_id,
        "payment_session_id": session_id,
        "amount_inr": amount,
        "plan": plan,
        "mode": cashfree.mode(),
        "return_url": return_url.replace("{order_id}", order_id),
        "payment_methods": cashfree.payment_methods(),
    })


@bp.get("/orders/<order_id>")
@require("owner", allow_when_locked=True)
def order_status(order_id: str):
    db = get_db()
    local = db.billing_orders.find_one({"order_id": order_id, "workspace_id": g.ws_id})
    if not local:
        raise ApiError("Order not found", 404)

    remote: dict = {}
    payments: list = []
    try:
        remote = cashfree.get_order(order_id)
        payments = cashfree.get_payments(order_id)
    except ApiError:
        pass

    paid = cashfree.order_is_paid(remote, payments) or local.get("status") == "paid"
    if paid and local.get("status") != "paid":
        payment_id = None
        for p in payments:
            if (p.get("payment_status") or "").upper() == "SUCCESS":
                payment_id = p.get("cf_payment_id") or p.get("payment_id")
                break
        _mark_paid(local, {
            "payment_id": payment_id,
            "order_status": remote.get("order_status"),
            "payments": payments,
        })
        local = db.billing_orders.find_one({"order_id": order_id})

    return jsonify(ser({
        "order_id": order_id,
        "plan": local.get("plan"),
        "amount_inr": local.get("amount_inr"),
        "status": local.get("status"),
        "cf_status": remote.get("order_status"),
        "paid": local.get("status") == "paid",
        "workspace_plan": (db.workspaces.find_one({"_id": g.ws_id}) or {}).get("plan"),
        "payment_methods_used": [
            p.get("payment_group") or p.get("payment_method")
            for p in payments if (p.get("payment_status") or "").upper() == "SUCCESS"
        ],
    }))


def _mark_paid(local: dict, remote: dict | None = None) -> None:
    db = get_db()
    order_id = local["order_id"]
    if local.get("status") == "paid":
        return
    payment_id = None
    if remote:
        payment_id = remote.get("payment_id") or remote.get("cf_payment_id")
        payments = remote.get("payments")
        if not payment_id and isinstance(payments, list) and payments:
            for p in payments:
                if (p.get("payment_status") or "").upper() == "SUCCESS":
                    payment_id = p.get("cf_payment_id") or p.get("payment_id")
                    break
            if not payment_id:
                payment_id = payments[0].get("cf_payment_id")
    db.billing_orders.update_one(
        {"_id": local["_id"], "status": {"$ne": "paid"}},
        {"$set": {"status": "paid", "paid_at": now(), "updated_at": now(), "payment_id": payment_id, "raw_paid": remote or {}}},
    )
    ws = _apply_plan(local["workspace_id"], local["plan"], payment={
        "order_id": order_id, "payment_id": payment_id, "amount_inr": local.get("amount_inr"),
    })
    audit("billing.paid", "workspace", local["workspace_id"], {
        "plan": local["plan"], "order_id": order_id, "from": None, "to": ws.get("plan"),
    })
    log.info("plan upgraded via cashfree order=%s plan=%s ws=%s", order_id, local["plan"], local["workspace_id"])


@bp.post("/webhook")
def webhook():
    """Cashfree notify_url + dashboard webhook — verify HMAC signature."""
    raw = request.get_data(as_text=True) or ""
    signature = request.headers.get("x-webhook-signature") or ""
    timestamp = request.headers.get("x-webhook-timestamp") or ""
    if cashfree.enabled() and not cashfree.verify_webhook_signature(signature, raw, timestamp):
        if Config.CASHFREE_ENV == "production":
            log.warning("cashfree webhook signature mismatch")
            return jsonify({"ok": False, "error": "invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    data = payload.get("data") or payload
    order = data.get("order") or {}
    payment = data.get("payment") or {}
    order_id = order.get("order_id") or data.get("order_id") or payload.get("orderId")
    event_type = (payload.get("type") or payload.get("event") or "").upper()

    if not order_id:
        return jsonify({"ok": True, "ignored": True})

    db = get_db()
    local = db.billing_orders.find_one({"order_id": order_id})
    if not local:
        log.info("cashfree webhook unknown order %s type=%s", order_id, event_type)
        return jsonify({"ok": True, "unknown_order": True})

    success_events = ("PAYMENT_SUCCESS", "PAYMENT_CHARGES_WEBHOOK", "ORDER_PAID")
    paid_hint = (
        event_type in success_events
        or (payment.get("payment_status") or "").upper() == "SUCCESS"
        or (order.get("order_status") or "").upper() in ("PAID", "ACTIVE")
    )

    if paid_hint:
        _mark_paid(local, {
            "payment_id": payment.get("cf_payment_id"),
            "order_status": order.get("order_status"),
            "event": event_type,
            "payment_group": payment.get("payment_group") or payment.get("payment_method"),
        })
    else:
        db.billing_orders.update_one({"_id": local["_id"]}, {"$set": {
            "updated_at": now(), "last_webhook_type": event_type,
            "last_webhook_payment_status": payment.get("payment_status"),
        }})

    return jsonify({"ok": True})
