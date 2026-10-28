from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..db import get_db
from ..plans import require_feature
from ..security import require
from ..services import reports
from ..utils import ApiError, clamp_int, maybe_oid, now, oid, parse_dt, ser, token, valid_email
from . import body

bp = Blueprint("reports", __name__)


def _out(doc: dict, full: bool = False) -> dict:
    o = ser(doc)
    if not full:
        o.pop("data", None)
        o["summary"] = doc["data"]["summary"]
    o["share_url"] = reports.share_url(doc) if not doc.get("revoked") else None
    o["share_active"] = not doc.get("revoked") and (not doc.get("share_expires_at") or doc["share_expires_at"] > now())
    return o


def _scoped_client(cid):
    cid = maybe_oid(cid)
    if g.role == "client":
        allowed = g.member.get("client_ids", [])
        if not cid or cid not in allowed:
            raise ApiError("You can only access reports for your assigned clients", 403)
    if cid and not get_db().clients.find_one({"_id": cid, "workspace_id": g.ws_id}):
        raise ApiError("Client not found", 404)
    return cid


@bp.get("/api/reports")
@require()
def list_reports():
    q = {"workspace_id": g.ws_id}
    if g.role == "client":
        q["client_id"] = {"$in": g.member.get("client_ids", [])}
    if request.args.get("client_id"):
        q["client_id"] = oid(request.args["client_id"])
    rows = list(get_db().reports.find(q).sort("created_at", -1).limit(100))
    clients = {c["_id"]: c["name"] for c in get_db().clients.find({"workspace_id": g.ws_id})}
    out = []
    for r in rows:
        o = _out(r)
        o["client_name"] = clients.get(r.get("client_id"))
        out.append(o)
    return jsonify(out)


@bp.post("/api/reports")
@require("member")
def create():
    require_feature(g.ws, "reports", "Client reports")
    data = body()
    cid = _scoped_client(data.get("client_id"))
    end = parse_dt(data.get("end"), now())
    start = parse_dt(data.get("start"), end - timedelta(days=clamp_int(data.get("days"), 1, 365, 30)))
    if start >= end:
        raise ApiError("Start date must be before end date", 422)
    doc = reports.create_report(g.ws, cid, start, end, g.user["_id"], clamp_int(data.get("share_days"), 1, 365, 30))
    audit("report.created", "report", doc["_id"], {"client_id": str(cid) if cid else None})
    return jsonify(_out(doc, True)), 201


@bp.get("/api/reports/<rid>")
@require()
def get_report(rid):
    doc = get_db().reports.find_one({"_id": oid(rid), "workspace_id": g.ws_id})
    if not doc:
        raise ApiError("Report not found", 404)
    if g.role == "client" and doc.get("client_id") not in g.member.get("client_ids", []):
        raise ApiError("Report not found", 404)
    return jsonify(_out(doc, True))


@bp.patch("/api/reports/<rid>/share")
@require("member")
def share(rid):
    db = get_db()
    doc = db.reports.find_one({"_id": oid(rid), "workspace_id": g.ws_id})
    if not doc:
        raise ApiError("Report not found", 404)
    data = body()
    upd = {}
    if data.get("action") == "revoke":
        upd = {"revoked": True}
    elif data.get("action") == "renew":
        upd = {"revoked": False, "share_token": token("r_", 18),
               "share_expires_at": now() + timedelta(days=clamp_int(data.get("days"), 1, 365, 30))}
    else:
        raise ApiError("action must be 'revoke' or 'renew'", 422)
    db.reports.update_one({"_id": doc["_id"]}, {"$set": upd})
    audit(f"report.share_{data['action']}", "report", doc["_id"])
    return jsonify(_out(db.reports.find_one({"_id": doc["_id"]})))


@bp.delete("/api/reports/<rid>")
@require("member")
def delete(rid):
    res = get_db().reports.delete_one({"_id": oid(rid), "workspace_id": g.ws_id})
    if not res.deleted_count:
        raise ApiError("Report not found", 404)
    return jsonify({"ok": True})


@bp.get("/api/public/reports/<tok>")
def public_report(tok):
    doc = get_db().reports.find_one({"share_token": tok})
    if not doc or doc.get("revoked") or (doc.get("share_expires_at") and doc["share_expires_at"] < now()):
        raise ApiError("This report link has expired or been revoked", 404)
    return jsonify({"title": doc["title"], "data": doc["data"], "expires_at": ser(doc.get("share_expires_at"))})


# ------------------------------------------------------------------ schedules


@bp.get("/api/report-schedules")
@require("member")
def list_schedules():
    clients = {c["_id"]: c["name"] for c in get_db().clients.find({"workspace_id": g.ws_id})}
    rows = list(get_db().report_schedules.find({"workspace_id": g.ws_id}).sort("created_at", -1))
    for r in rows:
        r["client_name"] = clients.get(r.get("client_id"))
    return jsonify(ser(rows))


@bp.post("/api/report-schedules")
@require("member")
def create_schedule():
    require_feature(g.ws, "scheduled_reports", "Scheduled reports")
    data = body()
    recipients = [e.strip().lower() for e in data.get("recipients") or [] if e.strip()]
    if not recipients or not all(valid_email(e) for e in recipients):
        raise ApiError("Add at least one valid recipient email", 422)
    freq = data.get("frequency") if data.get("frequency") in ("weekly", "monthly") else "weekly"
    doc = {"workspace_id": g.ws_id, "client_id": _scoped_client(data.get("client_id")), "frequency": freq, "recipients": recipients,
           "active": True, "created_at": now(), "next_run_at": now() + timedelta(days=7 if freq == "weekly" else 30)}
    if data.get("send_now"):
        doc["next_run_at"] = now()
    doc["_id"] = get_db().report_schedules.insert_one(doc).inserted_id
    audit("report_schedule.created", "report_schedule", doc["_id"])
    return jsonify(ser(doc)), 201


@bp.patch("/api/report-schedules/<sid>")
@require("member")
def update_schedule(sid):
    data = body()
    upd = {}
    if "active" in data:
        upd["active"] = bool(data["active"])
    if data.get("run_now"):
        upd["next_run_at"] = now()
    res = get_db().report_schedules.update_one({"_id": oid(sid), "workspace_id": g.ws_id}, {"$set": upd})
    if not res.matched_count:
        raise ApiError("Schedule not found", 404)
    return jsonify(ser(get_db().report_schedules.find_one({"_id": oid(sid)})))


@bp.delete("/api/report-schedules/<sid>")
@require("member")
def delete_schedule(sid):
    get_db().report_schedules.delete_one({"_id": oid(sid), "workspace_id": g.ws_id})
    return jsonify({"ok": True})
