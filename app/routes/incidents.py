import re
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..db import get_db
from ..security import client_scope, require, sign_artifact
from ..services import ai, notify
from ..services.incidents import add_timeline, _link
from ..utils import ApiError, clamp_int, maybe_oid, now, oid, ser, valid_email
from . import body

bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")

STATUSES = ("open", "investigating", "resolved", "ignored")

_NOISE_HOST = re.compile(
    r"(google-analytics\.com|googletagmanager\.com|googleadservices\.com|"
    r"doubleclick\.net|googlesyndication\.com|google\.com/(ccm|rmkt|pagead|recaptcha)|"
    r"facebook\.net|facebook\.com/(tr|en_US/fbevents)|connect\.facebook\.net|"
    r"hotjar\.com|clarity\.ms|segment\.io|segment\.com|mixpanel\.com|"
    r"sentry\.io|newrelic\.com|nr-data\.net|fullstory\.com|heap-api\.com|"
    r"cdn\.amplitude\.com|api\.amplitude\.com)",
    re.I,
)
_NOISE_CONSOLE = re.compile(
    r"(ReactGA\.initialize|moment construction falls back|Download the React DevTools|"
    r"\[HMR\]|\[webpack-dev-server\]|Deprecation warning: value provided is not in a recognized RFC2822)",
    re.I,
)
_WORKER_ERROR = re.compile(r"Browser worker error|Executable doesn.?t exist|playwright", re.I)


def _noise_url(url: str) -> bool:
    return bool(_NOISE_HOST.search(url or ""))


def _noise_console(text: str) -> bool:
    return bool(_NOISE_CONSOLE.search(text or ""))


def _worker_error(text: str) -> bool:
    return bool(_WORKER_ERROR.search(text or ""))


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
        r["assignee_email"] = r.get("assignee_email") or members.get(r.get("assignee_id"))
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
                console = [c for c in (r.get("console") or []) if not _noise_console(c.get("text") or "")][:10]
                nets = [n for n in (r.get("network_failures") or []) if not _noise_url(n.get("url") or "")][:10]
                item["run"] = {"id": str(r["_id"]), "ok": r["ok"], "error": r.get("error"),
                               "steps": ser(r.get("steps")), "console": console,
                               "network_failures": nets,
                               "screenshot_url": sign_artifact(r.get("screenshot")),
                               "infra": bool(r.get("classification") == "infra" or _worker_error(r.get("error") or ""))}
        ev_out.append(item)
    o["evidence"] = ev_out[::-1]
    if inc.get("website_id"):
        o["website"] = ser(db.websites.find_one({"_id": inc["website_id"]}, {"name": 1, "url": 1, "status": 1}))
    if inc.get("client_id"):
        o["client"] = ser(db.clients.find_one({"_id": inc["client_id"]}, {"name": 1}))
    o["assignee_email"] = inc.get("assignee_email")
    if not o["assignee_email"] and inc.get("assignee_id"):
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
    if "assignee_id" in data or "assignee_email" in data:
        aid = maybe_oid(data.get("assignee_id")) if data.get("assignee_id") else None
        email_in = (data.get("assignee_email") or "").strip().lower() or None
        if email_in and not valid_email(email_in):
            raise ApiError("Enter a valid assignee email", 422)
        m = None
        if aid:
            m = db.members.find_one({"workspace_id": g.ws_id, "user_id": aid, "role": {"$ne": "client"}})
        elif email_in:
            m = db.members.find_one({"workspace_id": g.ws_id, "email": email_in, "role": {"$ne": "client"}})
        elif data.get("assignee_id") in (None, "", "null") and not email_in and "assignee_id" in data:
            m = None  # explicit unassign
        if (aid or email_in) and not m:
            raise ApiError("Assignee must be a workspace team member. Invite them under Settings → Team first.", 422)
        email = m["email"] if m else None
        new_aid = m.get("user_id") if m else None
        prev_email = inc.get("assignee_email")
        if not prev_email and inc.get("assignee_id"):
            prev = db.members.find_one({"workspace_id": g.ws_id, "user_id": inc["assignee_id"]})
            prev_email = prev["email"] if prev else None
        upd["assignee_id"] = new_aid
        upd["assignee_email"] = email
        if not inc.get("acknowledged_at"):
            upd["acknowledged_at"] = now()
        add_timeline(inc["_id"], "assigned", f"Assigned to {email}" if email else "Unassigned", who)
        # Email the assignee (once) when ownership changes to them.
        if email and email != prev_email and email.lower() != (who or "").lower():
            site = None
            if inc.get("website_id"):
                w = db.websites.find_one({"_id": inc["website_id"]}, {"name": 1, "url": 1})
                site = (w or {}).get("name") or (w or {}).get("url")
            notify.dispatch(
                g.ws,
                "assignment",
                f"Assigned to you: {inc['title']}",
                f"{who} assigned this {inc.get('severity', 'major')} incident to you.\n\n"
                f"{inc.get('summary') or inc['title']}\n\n"
                f"Open it in Watchfront to investigate and update status.",
                severity=inc.get("severity") or "major",
                incident_id=inc["_id"],
                link=_link(inc["_id"]),
                extra_emails=[email],
                kind=inc.get("source_type") or "browser_test",
                site=site,
                force=True,
            )
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
