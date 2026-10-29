from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..config import Config
from ..db import get_db
from ..plans import PLANS, limits, usage
from ..security import require, validate_target
from ..services import notify
from ..utils import ApiError, clamp_int, now, oid, ser, valid_email
from . import body

bp = Blueprint("workspace", __name__, url_prefix="/api/workspace")


def _ws_payload(ws: dict) -> dict:
    out = ser(ws)
    out["limits"] = limits(ws)
    out["usage"] = usage(ws)
    out["notifications"] = notify.settings_for(ws)
    out["role"] = g.role
    out["smtp_configured"] = bool(Config.SMTP_HOST)
    out["ai_engine"] = Config.OPENAI_MODEL if Config.OPENAI_API_KEY else "heuristic"
    return out


@bp.get("")
@require()
def get_ws():
    return jsonify(_ws_payload(g.ws))


@bp.patch("")
@require("admin")
def update_ws():
    data = body()
    upd = {}
    if "name" in data and str(data["name"]).strip():
        upd["name"] = str(data["name"]).strip()[:80]
    if "branding" in data:
        b = data["branding"] or {}
        if (b.get("company_name") or b.get("logo_url")) and not limits(g.ws)["white_label"]:
            raise ApiError("White-label branding requires the Agency Pro plan", 402, "plan_limit")
        upd["branding"] = {"company_name": str(b.get("company_name") or "")[:80], "logo_url": str(b.get("logo_url") or "")[:500],
                           "primary_color": str(b.get("primary_color") or "#9B1B67")[:9]}
    if "settings" in data:
        s = data["settings"] or {}
        upd["settings"] = {**(g.ws.get("settings") or {}), "ai_enabled": bool(s.get("ai_enabled", True)),
                           "collect_query_strings": bool(s.get("collect_query_strings", False))}
    if upd:
        get_db().workspaces.update_one({"_id": g.ws_id}, {"$set": upd})
        audit("workspace.updated", "workspace", g.ws_id, {"fields": list(upd)})
    return jsonify(_ws_payload(get_db().workspaces.find_one({"_id": g.ws_id})))


@bp.put("/notifications")
@require("admin")
def update_notifications():
    data = body()
    emails = [e.strip().lower() for e in data.get("emails") or [] if e.strip()]
    bad = [e for e in emails if not valid_email(e)]
    if bad:
        raise ApiError(f"Invalid email: {bad[0]}", 422)
    for field in ("slack_webhook", "teams_webhook", "webhook_url"):
        url = (data.get(field) or "").strip()
        if url:
            ok, reason = validate_target(url)
            if not ok or not url.startswith("https://"):
                raise ApiError(f"{field.replace('_', ' ')} must be a public https URL ({reason or 'https required'})", 422)
    if data.get("slack_webhook") and not limits(g.ws)["slack"]:
        raise ApiError("Slack/Teams notifications require the Agency plan", 402, "plan_limit")
    esc = data.get("escalation") or {}
    quiet = data.get("quiet_hours") or {}

    def _hhmm(v: str, default: str) -> str:
        raw = (v or default).strip()
        parts = raw.split(":")
        try:
            h, m = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            if 0 <= h <= 23 and 0 <= m <= 59:
                return f"{h:02d}:{m:02d}"
        except (TypeError, ValueError):
            pass
        return default

    settings = {
        "emails": emails,
        "slack_webhook": (data.get("slack_webhook") or "").strip(),
        "teams_webhook": (data.get("teams_webhook") or "").strip(),
        "webhook_url": (data.get("webhook_url") or "").strip(),
        "events": {k: bool(v) for k, v in (data.get("events") or {}).items() if k in notify.DEFAULT_SETTINGS["events"]},
        "min_severity": data.get("min_severity") if data.get("min_severity") in notify.SEVERITY_RANK else "minor",
        "escalation": {"enabled": bool(esc.get("enabled")), "after_minutes": clamp_int(esc.get("after_minutes"), 5, 1440, 30),
                       "emails": [e.strip().lower() for e in esc.get("emails") or [] if valid_email(e.strip())]},
        "quiet_hours": {
            "enabled": bool(quiet.get("enabled")),
            "start": _hhmm(str(quiet.get("start") or ""), "22:00"),
            "end": _hhmm(str(quiet.get("end") or ""), "07:00"),
        },
    }
    get_db().workspaces.update_one({"_id": g.ws_id}, {"$set": {"notifications": settings}})
    audit("notifications.updated", "workspace", g.ws_id)
    return jsonify(notify.settings_for({**g.ws, "notifications": settings}))


@bp.post("/notifications/test")
@require("admin")
def test_notification():
    notify.dispatch(g.ws, "incident_opened", "Test notification", "This is a test alert from Watchfront. Your notification channel works.",
                    severity="critical", link=f"{Config.APP_URL}/app")
    last = list(get_db().notifications.find({"workspace_id": g.ws_id}).sort("at", -1).limit(4))
    return jsonify(ser(last))


@bp.get("/notifications/log")
@require("member")
def notification_log():
    rows = get_db().notifications.find({"workspace_id": g.ws_id}).sort("at", -1).limit(clamp_int(request.args.get("limit"), 1, 500, 100))
    return jsonify(ser(list(rows)))


# ------------------------------------------------------------------ members


@bp.get("/members")
@require()
def members():
    rows = list(get_db().members.find({"workspace_id": g.ws_id}).sort("created_at", 1))
    users = {u["_id"]: u for u in get_db().users.find({"_id": {"$in": [r.get("user_id") for r in rows if r.get("user_id")]}})}
    for r in rows:
        u = users.get(r.get("user_id"))
        r["name"] = u.get("name") if u else None
    return jsonify(ser(rows))


@bp.post("/members")
@require("admin")
def invite():
    data = body()
    email = (data.get("email") or "").strip().lower()
    role = data.get("role", "member")
    if not valid_email(email):
        raise ApiError("Enter a valid email", 422)
    if role not in ("admin", "member", "client"):
        raise ApiError("Invalid role", 422)
    db = get_db()
    count = db.members.count_documents({"workspace_id": g.ws_id, "role": {"$ne": "client"}})
    if role != "client" and count >= limits(g.ws)["team_members"]:
        raise ApiError(f"Your plan allows {limits(g.ws)['team_members']} team members", 402, "plan_limit")
    if db.members.find_one({"workspace_id": g.ws_id, "email": email}):
        raise ApiError("This person is already a member or invited", 409)
    user = db.users.find_one({"email": email})
    client_ids = [oid(c) for c in data.get("client_ids") or []]
    doc = {"workspace_id": g.ws_id, "email": email, "role": role, "client_ids": client_ids, "created_at": now(),
           "user_id": user["_id"] if user else None, "status": "active" if user else "invited", "invited_by": g.user["_id"]}
    doc["_id"] = db.members.insert_one(doc).inserted_id
    notify.send_email([email], f"You've been invited to {g.ws['name']} on Watchfront",
                      f"{g.user.get('name') or g.user['email']} invited you to join {g.ws['name']} as {role}.\n"
                      f"{'Sign in' if user else 'Create an account with this email'} at {Config.APP_URL}/{'login' if user else 'register'}")
    audit("member.invited", "member", doc["_id"], {"email": email, "role": role})
    return jsonify(ser(doc)), 201


@bp.patch("/members/<mid>")
@require("admin")
def update_member(mid):
    db = get_db()
    m = db.members.find_one({"_id": oid(mid), "workspace_id": g.ws_id})
    if not m:
        raise ApiError("Member not found", 404)
    if m["role"] == "owner":
        raise ApiError("The owner's role cannot be changed", 403)
    data = body()
    upd = {}
    if data.get("role") in ("admin", "member", "client"):
        upd["role"] = data["role"]
    if "client_ids" in data:
        upd["client_ids"] = [oid(c) for c in data["client_ids"] or []]
    db.members.update_one({"_id": m["_id"]}, {"$set": upd})
    audit("member.updated", "member", m["_id"], {k: str(v) for k, v in upd.items()})
    return jsonify(ser(db.members.find_one({"_id": m["_id"]})))


@bp.delete("/members/<mid>")
@require("admin")
def remove_member(mid):
    db = get_db()
    m = db.members.find_one({"_id": oid(mid), "workspace_id": g.ws_id})
    if not m:
        raise ApiError("Member not found", 404)
    if m["role"] == "owner":
        raise ApiError("The workspace owner cannot be removed", 403)
    db.members.delete_one({"_id": m["_id"]})
    audit("member.removed", "member", m["_id"], {"email": m["email"]})
    return jsonify({"ok": True})


# ------------------------------------------------------------------ billing


@bp.get("/plans")
@require()
def plans():
    return jsonify({"current": g.ws.get("plan"), "plans": PLANS, "usage": usage(g.ws)})


@bp.post("/plan")
@require("owner")
def change_plan():
    """Downgrade to Free when Cashfree is enabled; paid upgrades go through /api/billing/checkout."""
    from ..services import cashfree
    plan = body().get("plan")
    if plan not in PLANS or plan == "enterprise":
        raise ApiError("Choose a valid self-serve plan (Enterprise requires contacting sales)", 422)
    if cashfree.enabled() and plan != "free" and (PLANS[plan].get("price_inr") or 0) > 0:
        raise ApiError("Paid plans require Cashfree checkout. Use Pay & upgrade.", 402, "payment_required")
    db = get_db()
    new_limits = PLANS[plan]
    sites = db.websites.count_documents({"workspace_id": g.ws_id})
    if sites > new_limits["websites"]:
        raise ApiError(f"You have {sites} websites; the {new_limits['name']} plan allows {new_limits['websites']}. Remove some first.", 409)
    db.workspaces.update_one({"_id": g.ws_id}, {"$set": {"plan": plan, "trial": False, "plan_changed_at": now()}})
    db.websites.update_many({"workspace_id": g.ws_id, "interval_sec": {"$lt": new_limits["min_interval_sec"]}},
                            {"$set": {"interval_sec": new_limits["min_interval_sec"]}})
    audit("plan.changed", "workspace", g.ws_id, {"from": g.ws.get("plan"), "to": plan})
    return jsonify(_ws_payload(db.workspaces.find_one({"_id": g.ws_id})))


@bp.get("/audit")
@require("admin")
def audit_log():
    rows = get_db().audit_events.find({"workspace_id": g.ws_id}).sort("at", -1).limit(clamp_int(request.args.get("limit"), 1, 500, 200))
    return jsonify(ser(list(rows)))
