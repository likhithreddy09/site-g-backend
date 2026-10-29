from datetime import timedelta

from flask import Blueprint, g, jsonify

from ..config import Config
from ..db import get_db
from ..plans import limits, usage
from ..security import client_scope, require
from ..utils import now, ser

bp = Blueprint("dashboard", __name__, url_prefix="/api")


@bp.get("/dashboard")
@require()
def overview():
    db = get_db()
    scope = {"workspace_id": g.ws_id, **client_scope()}
    sites = list(db.websites.find(scope, {"name": 1, "url": 1, "status": 1, "last_response_ms": 1, "last_check_at": 1,
                                          "last_status_code": 1, "client_id": 1, "ssl": 1, "domain": 1, "paused": 1,
                                          "ssl_enabled": 1, "domain_enabled": 1}))
    status_counts: dict[str, int] = {}
    for s in sites:
        status_counts[s.get("status", "unknown")] = status_counts.get(s.get("status", "unknown"), 0) + 1
    since = now() - timedelta(hours=24)
    site_ids = [s["_id"] for s in sites]
    total = db.check_results.count_documents({"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}})
    ok = db.check_results.count_documents({"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}, "ok": True})
    transient = db.check_results.count_documents({"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}, "classification": "transient"})
    avg = list(db.check_results.aggregate([{"$match": {"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}}},
                                           {"$group": {"_id": None, "avg": {"$avg": "$response_ms"}}}]))
    hourly = list(db.check_results.aggregate([
        {"$match": {"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}}},
        {"$group": {"_id": {"$dateTrunc": {"date": "$at", "unit": "hour"}}, "avg": {"$avg": "$response_ms"}, "n": {"$sum": 1},
                    "fail": {"$sum": {"$cond": ["$ok", 0, 1]}}}},
        {"$sort": {"_id": 1}}]))
    open_incidents = list(db.incidents.find({**scope, "status": {"$in": ["open", "investigating"]}},
                                            {"evidence": 0, "timeline": 0, "ai": 0}).sort("last_detected_at", -1).limit(8))
    names = {s["_id"]: s["name"] for s in sites}
    for i in open_incidents:
        i["website_name"] = names.get(i.get("website_id"))
    expiring = []
    for s in sites:
        ssl = s.get("ssl") or {}
        if ssl.get("days_left") is not None:
            expiring.append({"website_id": s["_id"], "name": s["name"], "kind": "SSL", "days_left": ssl["days_left"],
                             "status": ssl.get("status"), "soon": ssl["days_left"] <= 30,
                             "expires_at": ssl.get("valid_to"), "detail": ssl.get("issuer")})
        dom = s.get("domain") or {}
        if dom.get("days_left") is not None:
            expiring.append({"website_id": s["_id"], "name": s["name"], "kind": "Domain", "days_left": dom["days_left"],
                             "status": dom.get("status"), "soon": dom["days_left"] <= 60,
                             "expires_at": dom.get("expires_at"), "detail": dom.get("registrar")})
    tests_failing = db.browser_tests.count_documents({**{"workspace_id": g.ws_id}, "status": "failing"})
    err_groups = db.error_groups.count_documents({"workspace_id": g.ws_id, "status": "active", "last_seen": {"$gte": since}})
    pending_changes = db.visual_changes.count_documents({"workspace_id": g.ws_id, "status": "pending_review"})
    week = now() - timedelta(days=7)
    mttr = list(db.incidents.aggregate([
        {"$match": {"workspace_id": g.ws_id, "status": "resolved", "false_positive": {"$ne": True}, "resolved_at": {"$gte": week}}},
        {"$group": {"_id": None, "avg": {"$avg": {"$subtract": ["$resolved_at", "$started_at"]}}, "n": {"$sum": 1}}}]))
    clients = {c["_id"]: c.get("name") for c in db.clients.find({"workspace_id": g.ws_id}, {"name": 1})}
    uptime_rows = list(db.check_results.aggregate([
        {"$match": {"website_id": {"$in": site_ids}, "kind": "http", "at": {"$gte": since}}},
        {"$group": {"_id": "$website_id", "n": {"$sum": 1}, "ok": {"$sum": {"$cond": ["$ok", 1, 0]}}}}]))
    uptime_map = {r["_id"]: round(r["ok"] / r["n"] * 100, 2) if r["n"] else None for r in uptime_rows}
    portfolio = []
    for s in sites:
        ssl, dom = s.get("ssl") or {}, s.get("domain") or {}
        portfolio.append({
            "id": s["_id"], "name": s["name"], "url": s.get("url"), "status": s.get("status"), "paused": s.get("paused"),
            "last_response_ms": s.get("last_response_ms"), "last_check_at": s.get("last_check_at"),
            "last_status_code": s.get("last_status_code"), "client_name": clients.get(s.get("client_id")),
            "uptime_24h": uptime_map.get(s["_id"]),
            "ssl": {"status": ssl.get("status"), "days_left": ssl.get("days_left"), "issuer": ssl.get("issuer"),
                    "http_redirects_to_https": ssl.get("http_redirects_to_https"), "enabled": s.get("ssl_enabled", True)} if ssl or s.get("ssl_enabled", True) else None,
            "domain": {"status": dom.get("status"), "days_left": dom.get("days_left"), "registrar": dom.get("registrar"),
                       "domain": dom.get("domain"), "enabled": s.get("domain_enabled", True)} if dom or s.get("domain_enabled", True) else None,
        })
    portfolio.sort(key=lambda x: (0 if x.get("status") == "down" else 1 if x.get("status") == "degraded" else 2, x["name"].lower()))

    attention = []
    for i in open_incidents:
        attention.append({
            "kind": "incident", "severity": i.get("severity") or "major", "title": i.get("title"),
            "href": f"/app/incidents/{i['_id']}", "meta": i.get("website_name"), "at": i.get("last_detected_at") or i.get("started_at"),
        })
    for s in sites:
        if s.get("status") == "down" and not s.get("paused"):
            attention.append({
                "kind": "down", "severity": "critical", "title": f"{s['name']} is down",
                "href": f"/app/websites/{s['_id']}", "meta": s.get("url"), "at": s.get("last_check_at"),
            })
    for e in sorted(expiring, key=lambda x: x["days_left"]):
        if e["days_left"] <= (14 if e["kind"] == "SSL" else 30):
            attention.append({
                "kind": "expiry", "severity": "critical" if e["days_left"] < 0 else "major" if e["days_left"] <= 7 else "minor",
                "title": f"{e['name']} {e['kind'].lower()} {'expired' if e['days_left'] < 0 else f'expires in {e['days_left']}d'}",
                "href": f"/app/websites/{e['website_id']}?tab=ssl", "meta": e["kind"], "at": e.get("expires_at"),
            })
    if tests_failing:
        attention.append({
            "kind": "journey", "severity": "major", "title": f"{tests_failing} user journey{'s' if tests_failing != 1 else ''} failing",
            "href": "/app/tests", "meta": "Browser tests", "at": None,
        })
    if err_groups:
        attention.append({
            "kind": "errors", "severity": "minor", "title": f"{err_groups} active browser error group{'s' if err_groups != 1 else ''} (24h)",
            "href": "/app/errors", "meta": "JS / network", "at": None,
        })
    if pending_changes:
        attention.append({
            "kind": "visual", "severity": "info", "title": f"{pending_changes} visual change{'s' if pending_changes != 1 else ''} awaiting review",
            "href": "/app/checks", "meta": "Content & visual", "at": None,
        })
    sev_rank = {"critical": 0, "major": 1, "minor": 2, "info": 3}
    attention.sort(key=lambda a: (sev_rank.get(a.get("severity"), 9), a.get("at") is None))

    return jsonify(ser({
        "websites": {"total": len(sites), "by_status": status_counts},
        "portfolio": portfolio,
        "uptime_24h": round(ok / total * 100, 2) if total else None,
        "checks_24h": total, "transient_24h": transient,
        "avg_response_ms": round(avg[0]["avg"]) if avg and avg[0]["avg"] else None,
        "hourly": [{"t": h["_id"], "avg_ms": round(h["avg"] or 0), "checks": h["n"], "failures": h["fail"]} for h in hourly],
        "open_incidents": open_incidents,
        "needs_attention": attention[:12],
        "incident_counts": {s: db.incidents.count_documents({**scope, "status": s}) for s in ("open", "investigating")},
        "expiring": sorted(expiring, key=lambda x: x["days_left"]),
        "tests_failing": tests_failing, "error_groups_24h": err_groups, "pending_visual_changes": pending_changes,
        "mttr_7d_min": round(mttr[0]["avg"] / 60000) if mttr and mttr[0]["avg"] else None,
        "resolved_7d": mttr[0]["n"] if mttr else 0,
        "plan": {"id": g.ws.get("plan"), **limits(g.ws)}, "usage": usage(g.ws),
        "system": system_status(),
    }))


def system_status() -> dict:
    db = get_db()
    t = now()
    workers = list(db.system.find({"kind": "worker", "heartbeat_at": {"$gte": t - timedelta(minutes=10)}}))
    alive = [w for w in workers if w["heartbeat_at"] >= t - timedelta(seconds=max(60, Config.DISPATCH_INTERVAL_SEC * 6))]
    overdue = db.websites.count_documents({"paused": {"$ne": True}, "next_check_at": {"$lt": t - timedelta(minutes=3)}})
    failed_jobs = db.job_log.count_documents({"at": {"$gte": t - timedelta(hours=1)}, "ok": False})
    failed_notifications = db.notifications.count_documents({"at": {"$gte": t - timedelta(hours=24)}, "status": "failed"})
    degraded = not alive or overdue > 0
    reasons = []
    if not alive:
        reasons.append("No monitoring worker heartbeat in the last minute — scheduled checks are not running.")
    if overdue:
        reasons.append(f"{overdue} checks are overdue by more than 3 minutes.")
    return {"degraded": degraded, "reasons": reasons, "workers": ser(alive), "overdue_checks": overdue,
            "failed_jobs_1h": failed_jobs, "failed_notifications_24h": failed_notifications}


@bp.get("/system/health")
@require()
def health():
    db = get_db()
    s = system_status()
    s["recent_job_failures"] = ser(list(db.job_log.find().sort("at", -1).limit(20)))
    return jsonify(s)
