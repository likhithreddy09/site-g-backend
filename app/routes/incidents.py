import re
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..db import get_db
from ..security import client_scope, require, sign_artifact
from ..services import ai
from ..services.incidents import add_timeline
from ..utils import ApiError, clamp_int, maybe_oid, now, oid, ser
from . import body

bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")

STATUSES = ("open", "investigating", "resolved", "ignored")


def _get(iid) -> dict:
    inc = get_db().incidents.find_one({"_id": oid(iid), "workspace_id": g.ws_id, **client_scope()})
    if not inc:
        raise ApiError("Incident not found", 404)
    return inc


@bp.get("")
@require()
def list_incidents():
    db = get_db()
    q = {"workspace_id": g.ws_id, **client_scope()}
    status = request.args.get("status", "active")
    if status == "active":
        q["status"] = {"$in": ["open", "investigating"]}
    elif status in STATUSES:
        q["status"] = status
    for f in ("website_id", "client_id", "assignee_id"):
        if request.args.get(f):
            q[f] = maybe_oid(request.args[f])
    if request.args.get("severity"):
        q["severity"] = request.args["severity"]
    if request.args.get("source_type"):
        q["source_type"] = request.args["source_type"]
    if request.args.get("q"):
        q["title"] = {"$regex": re.escape(request.args["q"]), "$options": "i"}
    if request.args.get("false_positive") == "1":
        q["false_positive"] = True
    rows = list(db.incidents.find(q, {"evidence": 0, "timeline": 0, "ai": 0}).sort("last_detected_at", -1)
                .limit(clamp_int(request.args.get("limit"), 1, 500, 200)))
    sites = {s["_id"]: s["name"] for s in db.websites.find({"workspace_id": g.ws_id}, {"name": 1})}
    clients = {c["_id"]: c["name"] for c in db.clients.find({"workspace_id": g.ws_id}, {"name": 1})}
    members = {m["user_id"]: m["email"] for m in db.members.find({"workspace_id": g.ws_id}) if m.get("user_id")}
    for r in rows:
        r["website_name"] = sites.get(r.get("website_id"))
        r["client_name"] = clients.get(r.get("client_id"))
        r["assignee_email"] = members.get(r.get("assignee_id"))
    counts = {s: db.incidents.count_documents({"workspace_id": g.ws_id, "status": s, **client_scope()}) for s in STATUSES}
    return jsonify({"incidents": ser(rows), "counts": counts})


@bp.get("/<iid>")
@require()
def get_incident(iid):
    db = get_db()
    inc = _get(iid)
    o = ser(inc)
    ev_out = []
    for e in inc.get("evidence") or []:
        item = ser(e)
        if e.get("artifact"):
            item["artifact_url"] = sign_artifact(e["artifact"])
        if e.get("type") == "check_result" and e.get("ref_id"):
            r = db.check_results.find_one({"_id": e["ref_id"]}, {"status_code": 1, "response_ms": 1, "error": 1, "attempts": 1, "kind": 1, "details": 1})
            if r:
                item["result"] = ser(r)
        if e.get("type") == "test_run" and e.get("ref_id"):
            r = db.test_runs.find_one({"_id": e["ref_id"]})
            if r:
                item["run"] = {"id": str(r["_id"]), "ok": r["ok"], "error": r.get("error"),
                               "steps": ser(r.get("steps")), "console": r.get("console", [])[:10],
                               "network_failures": r.get("network_failures", [])[:10],
                               "screenshot_url": sign_artifact(r.get("screenshot"))}
        ev_out.append(item)
    o["evidence"] = ev_out[::-1]
    if inc.get("website_id"):
        o["website"] = ser(db.websites.find_one({"_id": inc["website_id"]}, {"name": 1, "url": 1, "status": 1}))
    if inc.get("client_id"):
        o["client"] = ser(db.clients.find_one({"_id": inc["client_id"]}, {"name": 1}))
    if inc.get("assignee_id"):
        m = db.members.find_one({"workspace_id": g.ws_id, "user_id": inc["assignee_id"]})
        o["assignee_email"] = m["email"] if m else None
    o["related"] = ser(list(db.incidents.find({"workspace_id": g.ws_id, "website_id": inc.get("website_id"), "_id": {"$ne": inc["_id"]},
                                               "started_at": {"$gte": inc["started_at"] - timedelta(hours=24)}},
                                              {"title": 1, "status": 1, "severity": 1, "started_at": 1}).limit(10))) if inc.get("website_id") else []
    return jsonify(o)


@bp.patch("/<iid>")
@require("member")
def update_incident(iid):
    db = get_db()
    inc = _get(iid)
    data = body()
    upd, who = {}, g.user["email"]
    if "status" in data and data["status"] != inc["status"]:
        st = data["status"]
        if st not in STATUSES:
            raise ApiError("Invalid status", 422)
        upd["status"] = st
        if st == "resolved":
            upd["resolved_at"] = now()
            if data.get("resolution"):
                upd["resolution"] = str(data["resolution"])[:5000]
        elif st in ("open", "investigating"):
            upd["resolved_at"] = None
        if st == "investigating" and not inc.get("acknowledged_at"):
            upd["acknowledged_at"] = now()
        add_timeline(inc["_id"], "status", f"Status changed from {inc['status']} to {st}", who)
    if "severity" in data and data["severity"] in ("info", "minor", "major", "critical") and data["severity"] != inc["severity"]:
        upd["severity"] = data["severity"]
        add_timeline(inc["_id"], "severity", f"Severity changed to {data['severity']}", who)
    if "assignee_id" in data:
        aid = maybe_oid(data["assignee_id"])
        email = None
        if aid:
            m = db.members.find_one({"workspace_id": g.ws_id, "user_id": aid, "status": "active"})
            if not m:
                raise ApiError("Assignee is not a member of this workspace", 422)
            email = m["email"]
        upd["assignee_id"] = aid
        if not inc.get("acknowledged_at"):
            upd["acknowledged_at"] = now()
        add_timeline(inc["_id"], "assigned", f"Assigned to {email}" if email else "Unassigned", who)
    if "false_positive" in data:
        upd["false_positive"] = bool(data["false_positive"])
        if upd["false_positive"]:
            upd["status"] = "resolved"
            upd["resolved_at"] = now()
            upd["false_positive_reason"] = str(data.get("reason") or "")[:1000]
        add_timeline(inc["_id"], "false_positive", "Marked as false positive" + (f": {data.get('reason')}" if data.get("reason") else "")
                     if upd["false_positive"] else "False-positive flag removed", who)
    if "resolution" in data and "resolution" not in upd:
        upd["resolution"] = str(data["resolution"])[:5000]
        add_timeline(inc["_id"], "resolution", "Resolution summary updated", who)
    if "acknowledge" in data and not inc.get("acknowledged_at"):
        upd["acknowledged_at"] = now()
        add_timeline(inc["_id"], "acknowledged", "Incident acknowledged", who)
    if upd:
        db.incidents.update_one({"_id": inc["_id"]}, {"$set": upd})
        audit("incident.updated", "incident", inc["_id"], {k: str(v) for k, v in upd.items()})
    return get_incident(iid)


@bp.post("/<iid>/notes")
@require("member")
def add_note(iid):
    inc = _get(iid)
    text = (body().get("text") or "").strip()
    if not text:
        raise ApiError("Note cannot be empty", 422)
    note = {"at": now(), "by": g.user["email"], "text": text[:5000]}
    get_db().incidents.update_one({"_id": inc["_id"]}, {"$push": {"notes": note}})
    add_timeline(inc["_id"], "note", text[:200], g.user["email"])
    return get_incident(iid)


@bp.post("/<iid>/diagnose")
@require("member")
def diagnose(iid):
    inc = _get(iid)
    result = ai.diagnose(g.ws, inc)
    add_timeline(inc["_id"], "ai", "AI-assisted diagnosis generated", g.user["email"])
    audit("incident.ai_diagnosis", "incident", inc["_id"], {"engine": result["engine"]})
    return jsonify(ser(result))
