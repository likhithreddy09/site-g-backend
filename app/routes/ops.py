"""Ops-only endpoints gated by PIN + birth city (not product auth)."""
from __future__ import annotations

import hmac
from datetime import timedelta

from flask import Blueprint, jsonify

from ..config import Config
from ..db import get_db
from ..services import notify
from ..utils import ApiError, now, ser, valid_email
from . import body

bp = Blueprint("ops", __name__, url_prefix="/api/ops")


def _check_ops_gate(pin: str, city: str) -> None:
    expected_pin = Config.OPS_PIN or ""
    expected_city = (Config.OPS_BIRTH_CITY or "").strip().lower()
    got_pin = (pin or "").strip()
    got_city = (city or "").strip().lower()
    pin_ok = bool(expected_pin) and hmac.compare_digest(got_pin, expected_pin)
    city_ok = bool(expected_city) and hmac.compare_digest(got_city, expected_city)
    if not (pin_ok and city_ok):
        raise ApiError("Incorrect PIN or city", 403, "ops_forbidden")


@bp.post("/active-users")
def active_users():
    data = body()
    _check_ops_gate(str(data.get("pin") or ""), str(data.get("city") or ""))

    minutes = Config.OPS_LIVE_MINUTES
    try:
        if data.get("minutes") is not None:
            minutes = max(1, min(24 * 60, int(data.get("minutes"))))
    except (TypeError, ValueError):
        pass

    db = get_db()
    cutoff = now() - timedelta(minutes=minutes)
    live = list(
        db.users.find(
            {"last_seen_at": {"$gte": cutoff}},
            {"email": 1, "name": 1, "last_seen_at": 1, "last_login_at": 1, "created_at": 1},
        ).sort("last_seen_at", -1)
    )
    # Until last_seen builds up, also surface recent logins in the window
    recent_login = list(
        db.users.find(
            {
                "last_login_at": {"$gte": cutoff},
                "$or": [{"last_seen_at": {"$exists": False}}, {"last_seen_at": {"$lt": cutoff}}],
            },
            {"email": 1, "name": 1, "last_seen_at": 1, "last_login_at": 1, "created_at": 1},
        ).sort("last_login_at", -1)
    )

    all_users = list(
        db.users.find(
            {},
            {"email": 1, "name": 1, "last_seen_at": 1, "last_login_at": 1, "created_at": 1},
        ).sort([("created_at", -1), ("_id", -1)])
    )

    return jsonify(
        {
            "live_minutes": minutes,
            "total_users": len(all_users),
            "live_count": len(live),
            "live_users": ser(live),
            "recent_login_only": ser(recent_login),
            "all_users": ser(all_users),
            "as_of": ser(now()),
            "email": {
                "provider": notify.email_provider(),
                "configured": notify.email_provider() != "none",
                "from": Config.SMTP_FROM,
                "smtp_host": Config.SMTP_HOST or None,
                "smtp_port": Config.SMTP_PORT,
            },
        }
    )


@bp.post("/resend-welcome")
def resend_welcome():
    """Resend onboarding email to a user (ops gate)."""
    data = body()
    _check_ops_gate(str(data.get("pin") or ""), str(data.get("city") or ""))
    email = (data.get("email") or "").strip().lower()
    if not valid_email(email):
        raise ApiError("Enter a valid email", 422, "invalid_email")
    user = get_db().users.find_one({"email": email})
    if not user:
        raise ApiError("User not found", 404, "not_found")
    status, err = notify.send_welcome_email(user)
    return jsonify({"email": email, "status": status, "error": err})


@bp.post("/test-email")
def test_email():
    """Send a short SMTP probe to verify GoDaddy delivery from Railway."""
    data = body()
    _check_ops_gate(str(data.get("pin") or ""), str(data.get("city") or ""))
    email = (data.get("email") or "").strip().lower()
    if not valid_email(email):
        raise ApiError("Enter a valid email", 422, "invalid_email")
    status, err = notify.send_email(
        [email],
        "Watchfront SMTP test",
        "If you received this, Watchfront SMTP from production is working.",
        html="<p>If you received this, Watchfront SMTP from production is working.</p>",
    )
    return jsonify(
        {
            "email": email,
            "status": status,
            "error": err,
            "provider": notify.email_provider(),
            "from": Config.SMTP_FROM,
        }
    )
