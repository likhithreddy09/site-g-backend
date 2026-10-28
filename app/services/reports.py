import math
from collections import defaultdict
from datetime import timedelta

from ..config import Config
from ..db import get_db
from ..plans import feature
from ..utils import now, token
from . import notify


def _pct(a, b):
    return round(a / b * 100, 3) if b else None


def build_report(ws: dict, client_id, start, end) -> dict:
    db = get_db()
    site_q = {"workspace_id": ws["_id"]}
    client = None
    if client_id:
        site_q["client_id"] = client_id
        client = db.clients.find_one({"_id": client_id, "workspace_id": ws["_id"]})
    sites = list(db.websites.find(site_q))
    site_ids = [s["_id"] for s in sites]
    rows = []
    totals = defaultdict(float)
    daily = defaultdict(lambda: {"sum": 0.0, "n": 0, "fail": 0, "total": 0})
    for s in sites:
        q = {"website_id": s["_id"], "kind": "http", "at": {"$gte": start, "$lt": end}}
        results = list(db.check_results.find(q, {"ok": 1, "classification": 1, "response_ms": 1, "at": 1}))
        total = len(results)
        up = sum(1 for r in results if r["ok"])
        transient = sum(1 for r in results if r.get("classification") == "transient")
        times = sorted(r["response_ms"] for r in results if r.get("response_ms"))
        for r in results:
            d = daily[r["at"].strftime("%Y-%m-%d")]
            d["total"] += 1
            if not r["ok"]:
                d["fail"] += 1
            if r.get("response_ms"):
                d["sum"] += r["response_ms"]
                d["n"] += 1
        incs = db.incidents.count_documents({"website_id": s["_id"], "started_at": {"$gte": start, "$lt": end}})
        rows.append({
            "website_id": str(s["_id"]), "name": s["name"], "url": s["url"], "status": s.get("status"),
            "checks": total, "uptime_pct": _pct(up, total), "transient_failures": transient, "failed_checks": total - up,
            "avg_response_ms": round(sum(times) / len(times)) if times else None,
            "p95_response_ms": round(times[max(0, math.ceil(len(times) * 0.95) - 1)]) if times else None,
            "incidents": incs, "ssl_days_left": (s.get("ssl") or {}).get("days_left"),
            "ssl_status": (s.get("ssl") or {}).get("status"), "domain_days_left": (s.get("domain") or {}).get("days_left"),
        })
        totals["checks"] += total
        totals["up"] += up
    inc_q = {"workspace_id": ws["_id"], "started_at": {"$gte": start, "$lt": end}}
    if client_id:
        inc_q["$or"] = [{"client_id": client_id}, {"website_id": {"$in": site_ids}}]
    incidents = list(db.incidents.find(inc_q).sort("started_at", -1))
    inc_rows = []
    for i in incidents:
        dur = None
        if i.get("resolved_at"):
            dur = int((i["resolved_at"] - i["started_at"]).total_seconds() // 60)
        inc_rows.append({"id": str(i["_id"]), "title": i["title"], "severity": i["severity"], "status": i["status"],
                         "started_at": i["started_at"].isoformat(), "resolved_at": i["resolved_at"].isoformat() if i.get("resolved_at") else None,
                         "duration_min": dur, "resolution": i.get("resolution") or "", "false_positive": i.get("false_positive", False),
                         "source_type": i["source_type"]})
    real = [i for i in inc_rows if not i["false_positive"]]
    resolved = [i for i in real if i["status"] == "resolved"]
    durations = [i["duration_min"] for i in resolved if i["duration_min"] is not None]
    test_q = {"workspace_id": ws["_id"], "at": {"$gte": start, "$lt": end}}
    if client_id:
        test_q["website_id"] = {"$in": site_ids}
    runs = db.test_runs.count_documents(test_q)
    failed_runs = db.test_runs.count_documents({**test_q, "ok": False})
    trend = [{"date": k, "avg_response_ms": round(v["sum"] / v["n"]) if v["n"] else None,
              "uptime_pct": _pct(v["total"] - v["fail"], v["total"])} for k, v in sorted(daily.items())]
    white = feature(ws, "white_label")
    b = ws.get("branding") or {}
    return {
        "title": f"Website health report — {client['name'] if client else 'All clients'}",
        "client": {"id": str(client["_id"]), "name": client["name"]} if client else None,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "generated_at": now().isoformat(),
        "coverage": {"websites": len(sites), "checks_run": int(totals["checks"]), "journey_runs": runs,
                     "note": "Uptime is calculated from scheduled HTTP checks in the period. Gaps in monitoring (e.g. paused sites) are not counted as uptime."},
        "summary": {"uptime_pct": _pct(totals["up"], totals["checks"]), "incidents_detected": len(real),
                    "incidents_resolved": len(resolved), "incidents_open": len([i for i in real if i["status"] in ("open", "investigating")]),
                    "false_positives": len(inc_rows) - len(real), "mttr_min": round(sum(durations) / len(durations)) if durations else None,
                    "journey_runs": runs, "journey_failures": failed_runs},
        "websites": rows, "incidents": inc_rows[:200], "trend": trend,
        "actions": [{"title": i["title"], "resolution": i["resolution"], "resolved_at": i["resolved_at"]} for i in resolved if i["resolution"]][:50],
        "branding": {"name": b.get("company_name") or ws["name"], "logo_url": b.get("logo_url"), "color": b.get("primary_color") or "#9B1B67",
                     "white_label": True} if white else {"name": ws["name"], "logo_url": None, "color": "#9B1B67", "white_label": False},
    }


def create_report(ws: dict, client_id, start, end, created_by=None, share_days: int | None = 30) -> dict:
    db = get_db()
    data = build_report(ws, client_id, start, end)
    doc = {"workspace_id": ws["_id"], "client_id": client_id, "title": data["title"], "period_start": start, "period_end": end,
           "data": data, "created_at": now(), "created_by": created_by, "share_token": token("r_", 18),
           "share_expires_at": now() + timedelta(days=share_days) if share_days else None, "revoked": False}
    doc["_id"] = db.reports.insert_one(doc).inserted_id
    return doc


def share_url(doc: dict) -> str:
    return f"{Config.APP_URL}/r/{doc['share_token']}"


def run_scheduled_reports() -> None:
    db = get_db()
    for sch in db.report_schedules.find({"active": True, "next_run_at": {"$lte": now()}}):
        ws = db.workspaces.find_one({"_id": sch["workspace_id"]})
        if not ws or not feature(ws, "scheduled_reports"):
            continue
        days = 7 if sch["frequency"] == "weekly" else 30
        end = now()
        doc = create_report(ws, sch.get("client_id"), end - timedelta(days=days), end)
        s = doc["data"]["summary"]
        body = (f"{doc['title']}\nPeriod: last {days} days\nUptime: {s['uptime_pct']}%\nIncidents detected: {s['incidents_detected']} "
                f"(resolved {s['incidents_resolved']})\n\nView the full report: {share_url(doc)}")
        status, err = notify.send_email(sch.get("recipients") or [], f"[SiteGuard] {doc['title']}", body)
        db.notifications.insert_one({"workspace_id": ws["_id"], "event": "report_ready", "channel": "email",
                                     "target": ", ".join(sch.get("recipients") or []), "subject": doc["title"],
                                     "status": status, "error": err, "at": now()})
        db.report_schedules.update_one({"_id": sch["_id"]}, {"$set": {"last_run_at": now(), "last_report_id": doc["_id"],
                                                                       "next_run_at": now() + timedelta(days=days)}})
