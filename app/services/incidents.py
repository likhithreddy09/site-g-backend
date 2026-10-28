from datetime import timedelta

from ..config import Config
from ..db import get_db
from ..utils import now
from . import notify

REOPEN_WINDOW = timedelta(hours=24)
ACTIVE = ["open", "investigating"]


def _link(incident_id) -> str:
    return f"{Config.APP_URL}/app/incidents/{incident_id}"


def _event(kind: str, text: str, by: str = "system") -> dict:
    return {"at": now(), "type": kind, "by": by, "text": text}


def open_or_update(ws: dict, *, key: str, source_type: str, source_id, title: str, severity: str,
                   evidence: dict, website_id=None, client_id=None, summary: str = "") -> dict:
    """Group repeated failures into one incident, reopening recently resolved ones."""
    db = get_db()
    t = now()
    evidence = {**evidence, "at": evidence.get("at", t)}
    existing = db.incidents.find_one({"workspace_id": ws["_id"], "key": key, "status": {"$in": ACTIVE + ["ignored"]}},
                                     sort=[("started_at", -1)])
    if existing:
        db.incidents.update_one({"_id": existing["_id"]}, {
            "$set": {"last_detected_at": t, "summary": summary or existing.get("summary", "")},
            "$inc": {"occurrences": 1},
            "$push": {"evidence": {"$each": [evidence], "$slice": -50}},
        })
        return existing

    recent = db.incidents.find_one({"workspace_id": ws["_id"], "key": key, "status": "resolved",
                                    "resolved_at": {"$gte": t - REOPEN_WINDOW}}, sort=[("resolved_at", -1)])
    if recent and not recent.get("false_positive"):
        db.incidents.update_one({"_id": recent["_id"]}, {
            "$set": {"status": "open", "last_detected_at": t, "resolved_at": None, "severity": severity},
            "$inc": {"occurrences": 1, "reopen_count": 1},
            "$push": {"evidence": {"$each": [evidence], "$slice": -50},
                      "timeline": _event("reopened", "Issue detected again after resolution; incident reopened.")},
        })
        notify.dispatch(ws, "incident_reopened", f"Reopened: {title}", summary or title,
                        severity=severity, incident_id=recent["_id"], link=_link(recent["_id"]))
        return recent

    doc = {
        "workspace_id": ws["_id"], "website_id": website_id, "client_id": client_id,
        "source_type": source_type, "source_id": source_id, "key": key,
        "title": title, "summary": summary, "severity": severity, "status": "open",
        "started_at": t, "last_detected_at": t, "resolved_at": None, "acknowledged_at": None,
        "escalated_at": None, "assignee_id": None, "occurrences": 1, "reopen_count": 0,
        "false_positive": False, "resolution": "", "evidence": [evidence], "notes": [],
        "timeline": [_event("opened", f"Incident opened: {title}")], "ai": None,
    }
    doc["_id"] = db.incidents.insert_one(doc).inserted_id
    notify.dispatch(ws, "incident_opened", title, summary or title, severity=severity,
                    incident_id=doc["_id"], link=_link(doc["_id"]))
    return doc


def auto_resolve(ws: dict, key: str, message: str = "Monitoring confirmed recovery.") -> None:
    db = get_db()
    inc = db.incidents.find_one({"workspace_id": ws["_id"], "key": key, "status": {"$in": ACTIVE}})
    if not inc:
        return
    t = now()
    duration = int((t - inc["started_at"]).total_seconds())
    db.incidents.update_one({"_id": inc["_id"]}, {
        "$set": {"status": "resolved", "resolved_at": t, "auto_resolved": True,
                 "resolution": inc.get("resolution") or message},
        "$push": {"timeline": _event("resolved", message)},
    })
    mins = max(1, duration // 60)
    notify.dispatch(ws, "incident_resolved", f"Recovered: {inc['title']}",
                    f"{message} Total duration: ~{mins} min.", severity=inc["severity"],
                    incident_id=inc["_id"], link=_link(inc["_id"]))


def add_timeline(incident_id, kind: str, text: str, by: str) -> None:
    get_db().incidents.update_one({"_id": incident_id}, {"$push": {"timeline": _event(kind, text, by)}})


def run_escalations() -> None:
    db = get_db()
    for ws in db.workspaces.find({"notifications.escalation.enabled": True}):
        esc = notify.settings_for(ws)["escalation"]
        cutoff = now() - timedelta(minutes=int(esc.get("after_minutes", 30)))
        for inc in db.incidents.find({"workspace_id": ws["_id"], "status": "open", "acknowledged_at": None,
                                      "escalated_at": None, "started_at": {"$lte": cutoff},
                                      "severity": {"$in": ["major", "critical"]}}):
            db.incidents.update_one({"_id": inc["_id"]}, {"$set": {"escalated_at": now()},
                                                          "$push": {"timeline": _event("escalated", "No acknowledgement within escalation window; escalated.")}})
            notify.dispatch(ws, "escalation", f"Escalation: {inc['title']}",
                            f"This {inc['severity']} incident has been open for more than {esc['after_minutes']} minutes without acknowledgement.",
                            severity=inc["severity"], incident_id=inc["_id"], link=_link(inc["_id"]),
                            extra_emails=esc.get("emails") or None)
