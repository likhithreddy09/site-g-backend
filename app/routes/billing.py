"""Dodo Payments hosted checkout + webhook for plan upgrades.

Flow:
1. Server creates checkout session → checkout_url
2. Client redirects to Dodo hosted checkout
3. Server confirms via webhook (payment.succeeded) + optional order poll
"""
from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..config import Config
from ..db import get_db
from ..plans import BILLING_PERIOD_DAYS, PLANS, extend_paid_until
from ..security import require
from ..services import dodo
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
    ws = db.workspaces.find_one({"_id": ws_id}) or {}
    until = extend_paid_until(ws)
    upd = {
        "plan": plan,
        "trial": False,
        "trial_ends_at": None,
        "paid_until": until,
        "plan_changed_at": now(),
    }
    if payment:
        prev = (ws.get("billing") or {})
        upd["billing"] = {
            **prev,
            "provider": "dodo",
            "last_order_id": payment.get("order_id"),
            "last_payment_id": payment.get("payment_id"),
            "last_paid_at": now(),
            "paid_until": until,
            "period_days": BILLING_PERIOD_DAYS,
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
    return jsonify({
        "enabled": dodo.enabled(),
        "mode": dodo.mode() if dodo.enabled() else None,
        "currency": "INR",
        "provider": "dodo",
        "payment_methods": "upi,cc,dc,nb",
        "payment_methods_labels": [
            {"id": "upi", "label": "UPI"},
            {"id": "cc", "label": "Credit card"},
            {"id": "dc", "label": "Debit card"},
            {"id": "nb", "label": "Netbanking"},
        ],
        "requires_phone": False,
    })


@bp.post("/checkout")
@require("owner", allow_when_locked=True)
def checkout():
    if not dodo.enabled():
        raise ApiError(
            "Payments are not configured on this server. Set DODO_PAYMENTS_API_KEY on Railway.",
            503,
            "billing_unavailable",
        )
    data = body()
    plan = data.get("plan")
    if plan not in PAID_PLANS:
        raise ApiError("Choose a paid plan to checkout (Starter, Growth, or Agency).", 422, "invalid_plan")
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
    phone = dodo.normalize_phone(phone_raw)
    if phone and (len(phone) != 10 or phone[0] not in "6789"):
        raise ApiError(
            "Enter a valid 10-digit Indian mobile number (or leave blank — Dodo checkout can collect it).",
            422,
            "invalid_phone",
        )
    if phone and phone != dodo.normalize_phone(user.get("phone")):
        db.users.update_one({"_id": user_id}, {"$set": {"phone": phone}})

    order_id = f"wf_{str(g.ws_id)[-8:]}_{plan}_{token('', 8)}"
    return_url = f"{Config.APP_URL}/app/billing?order_id={order_id}"

    session = dodo.create_checkout(
        plan=plan,
        order_id=order_id,
        amount_inr=amount,
        customer_email=user.get("email") or "likhith.reddy@watchfront.in",
        customer_name=user.get("name") or user.get("email") or "Customer",
        customer_phone=phone or None,
        return_url=return_url,
    )

    doc = {
        "order_id": order_id,
        "session_id": session["session_id"],
        "checkout_url": session["checkout_url"],
        "product_id": session.get("product_id"),
        "workspace_id": g.ws_id,
        "user_id": user_id,
        "plan": plan,
        "amount_inr": amount,
        "currency": "INR",
        "status": "created",
        "provider": "dodo",
        "customer_phone": phone or None,
        "created_at": now(),
        "updated_at": now(),
    }
    db.billing_orders.insert_one(doc)
    audit("billing.checkout_started", "workspace", g.ws_id, {"plan": plan, "order_id": order_id, "amount_inr": amount, "provider": "dodo"})

    return jsonify({
        "order_id": order_id,
        "session_id": session["session_id"],
        "checkout_url": session["checkout_url"],
        "amount_inr": amount,
        "plan": plan,
        "mode": dodo.mode(),
        "return_url": return_url,
        "provider": "dodo",
    })


@bp.get("/orders/<order_id>")
@require("owner", allow_when_locked=True)
def order_status(order_id: str):
    db = get_db()
    local = db.billing_orders.find_one({"order_id": order_id, "workspace_id": g.ws_id})
    if not local:
        raise ApiError("Order not found", 404)
    return jsonify(ser({
        "order_id": order_id,
        "plan": local.get("plan"),
        "amount_inr": local.get("amount_inr"),
        "status": local.get("status"),
        "paid": local.get("status") == "paid",
        "workspace_plan": (db.workspaces.find_one({"_id": g.ws_id}) or {}).get("plan"),
        "provider": local.get("provider") or "dodo",
    }))


def _mark_paid(local: dict, remote: dict | None = None) -> None:
    db = get_db()
    order_id = local["order_id"]
    if local.get("status") == "paid":
        return
    payment_id = None
    if remote:
        payment_id = remote.get("payment_id") or remote.get("id")
    db.billing_orders.update_one(
        {"_id": local["_id"], "status": {"$ne": "paid"}},
        {"$set": {"status": "paid", "paid_at": now(), "updated_at": now(), "payment_id": payment_id, "raw_paid": remote or {}}},
    )
    ws = _apply_plan(local["workspace_id"], local["plan"], payment={
        "order_id": order_id, "payment_id": payment_id, "amount_inr": local.get("amount_inr"),
    })
    audit("billing.paid", "workspace", local["workspace_id"], {
        "plan": local["plan"], "order_id": order_id, "from": None, "to": ws.get("plan"), "provider": "dodo",
    })
    log.info("plan upgraded via dodo order=%s plan=%s ws=%s", order_id, local["plan"], local["workspace_id"])


@bp.post("/webhook")
def webhook():
    """Dodo Payments webhook — payment.succeeded unlocks the plan."""
    raw = request.get_data() or b""
    try:
        event = dodo.unwrap_webhook(raw, dict(request.headers))
    except ApiError as e:
        return jsonify({"ok": False, "error": e.message}), e.status

    event_type = (event.get("type") or "").lower()
    meta = dodo.payment_metadata(event)
    order_id = meta.get("order_id")

    if not order_id:
        # Fallback: some payloads nest metadata differently
        data = event.get("data") or {}
        if hasattr(data, "model_dump"):
            data = data.model_dump()
        md = data.get("metadata") if isinstance(data, dict) else None
        if isinstance(md, dict):
            order_id = md.get("order_id")

    if not order_id:
        log.info("dodo webhook without order_id type=%s", event_type)
        return jsonify({"ok": True, "ignored": True})

    db = get_db()
    local = db.billing_orders.find_one({"order_id": order_id})
    if not local:
        log.info("dodo webhook unknown order %s type=%s", order_id, event_type)
        return jsonify({"ok": True, "unknown_order": True})

    if event_type in ("payment.succeeded", "payment.succeeded".lower()) or event_type.endswith("payment.succeeded"):
        _mark_paid(local, meta.get("raw") or {"payment_id": meta.get("payment_id")})
    elif "succeeded" in event_type and "payment" in event_type:
        _mark_paid(local, meta.get("raw") or {"payment_id": meta.get("payment_id")})
    else:
        db.billing_orders.update_one({"_id": local["_id"]}, {"$set": {
            "updated_at": now(), "last_webhook_type": event_type,
        }})

    return jsonify({"ok": True})
