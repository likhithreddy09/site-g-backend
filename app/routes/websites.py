from datetime import timedelta

from flask import Blueprint, g, jsonify, request
from pymongo.errors import DuplicateKeyError

from ..audit import audit
from ..config import Config
from ..db import get_db
from ..plans import limits, require_capacity
from ..security import client_scope, normalize_url, require, validate_target
from ..services import checks
from ..utils import ApiError, clamp_int, maybe_oid, now, oid, ser, token
from . import body

bp = Blueprint("websites", __name__, url_prefix="/api")


# ------------------------------------------------------------------ clients


@bp.get("/clients")
@require()
def list_clients():
    db = get_db()
    q = {"workspace_id": g.ws_id}
    if g.role == "client":
        q["_id"] = {"$in": g.member.get("client_ids", [])}
    rows = list(db.clients.find(q).sort("name", 1))
    for c in rows:
        sites = list(db.websites.find({"workspace_id": g.ws_id, "client_id": c["_id"]}, {"status": 1}))
        c["website_count"] = len(sites)
        c["down_count"] = sum(1 for s in sites if s.get("status") == "down")
        c["open_incidents"] = db.incidents.count_documents({"workspace_id": g.ws_id, "client_id": c["_id"], "status": {"$in": ["open", "investigating"]}})
    return jsonify(ser(rows))


@bp.post("/clients")
@require("member")
def create_client():
    data = body()
    name = (data.get("name") or "").strip()
    if not name:
        raise ApiError("Client name is required", 422)
    doc = {"workspace_id": g.ws_id, "name": name[:100], "contact_email": (data.get("contact_email") or "").strip()[:200],
           "notes": (data.get("notes") or "")[:2000], "created_at": now()}
    doc["_id"] = get_db().clients.insert_one(doc).inserted_id
    audit("client.created", "client", doc["_id"], {"name": name})
    return jsonify(ser(doc)), 201


@bp.patch("/clients/<cid>")
@require("member")
def update_client(cid):
    data = body()
    upd = {k: str(data[k])[:2000] for k in ("name", "contact_email", "notes") if k in data}
    res = get_db().clients.update_one({"_id": oid(cid), "workspace_id": g.ws_id}, {"$set": upd})
    if not res.matched_count:
        raise ApiError("Client not found", 404)
    return jsonify(ser(get_db().clients.find_one({"_id": oid(cid)})))


@bp.delete("/clients/<cid>")
@require("admin")
def delete_client(cid):
    db = get_db()
    c = db.clients.find_one({"_id": oid(cid), "workspace_id": g.ws_id})
    if not c:
        raise ApiError("Client not found", 404)
    db.websites.update_many({"client_id": c["_id"]}, {"$set": {"client_id": None}})
    db.clients.delete_one({"_id": c["_id"]})
    audit("client.deleted", "client", c["_id"], {"name": c["name"]})
    return jsonify({"ok": True})


# ------------------------------------------------------------------ websites


def _website_fields(data: dict, ws: dict, existing: dict | None = None) -> dict:
    lim = limits(ws)
    out = {}
    if "url" in data or not existing:
        url = normalize_url(data.get("url", ""))
        ok, reason = validate_target(url)
        if not ok:
            raise ApiError(f"This URL cannot be monitored: {reason}", 422, "blocked_url")
        out["url"] = url
        out["normalized_url"] = url.rstrip("/").replace("://www.", "://")
    if "name" in data or not existing:
        from urllib.parse import urlparse
        out["name"] = (data.get("name") or "").strip()[:100] or urlparse(out.get("url") or existing["url"]).hostname
    if "client_id" in data:
        cid = maybe_oid(data.get("client_id"))
        if cid and not get_db().clients.find_one({"_id": cid, "workspace_id": ws["_id"]}):
            raise ApiError("Client not found", 404)
        out["client_id"] = cid
    if "interval_sec" in data or not existing:
        out["interval_sec"] = clamp_int(data.get("interval_sec"), lim["min_interval_sec"], 86400, max(300, lim["min_interval_sec"]))
    simple_ints = {"timeout_sec": (2, 60, 10), "retries": (0, 5, 2), "retry_delay_sec": (1, 30, 5),
                   "failure_threshold": (1, 10, 2), "slow_threshold_ms": (0, 60000, 0)}
    for k, (lo, hi, d) in simple_ints.items():
        if k in data or not existing:
            out[k] = clamp_int(data.get(k), lo, hi, d)
    if "expected_statuses" in data or not existing:
        codes = [int(c) for c in (data.get("expected_statuses") or []) if str(c).isdigit() and 100 <= int(c) <= 599]
        out["expected_statuses"] = codes or [200, 201, 202, 203, 204, 301, 302]
    for k in ("keyword_present", "keyword_absent", "labels"):
        if k in data or not existing:
            v = data.get(k) or []
            if isinstance(v, str):
                v = [x.strip() for x in v.split(",")]
            out[k] = [str(x)[:200] for x in v if str(x).strip()][:20]
    if "notes" in data or not existing:
        out["notes"] = (data.get("notes") or "")[:5000]
    if "environment" in data or not existing:
        env = str(data.get("environment") or "production").strip().lower()[:32]
        out["environment"] = env if env in ("production", "staging", "development", "preview") else "production"
    if "ssl_enabled" in data or not existing:
        out["ssl_enabled"] = bool(data.get("ssl_enabled", True)) and bool(lim["ssl"])
    if "domain_enabled" in data or not existing:
        out["domain_enabled"] = bool(data.get("domain_enabled", True)) and bool(lim["ssl"])
    if "ssl_reminder_days" in data:
        out["ssl_reminder_days"] = sorted({clamp_int(x, 1, 120, 14) for x in data["ssl_reminder_days"] or [30, 14, 7, 1]}, reverse=True)
    if "domain_reminder_days" in data:
        out["domain_reminder_days"] = sorted({clamp_int(x, 1, 180, 30) for x in data["domain_reminder_days"] or [60, 30, 14, 7]}, reverse=True)
    if "rum" in data:
        r = data["rum"] or {}
        out["rum"] = {"enabled": bool(r.get("enabled", True)), "sample_rate": max(0.01, min(1.0, float(r.get("sample_rate", 1.0)))),
                      "capture_api": bool(r.get("capture_api", True)), "alert_threshold": clamp_int(r.get("alert_threshold"), 1, 10000, 10),
                      "ignore_patterns": [str(x)[:200] for x in r.get("ignore_patterns") or [] if str(x).strip()][:30],
                      "release": str(r.get("release") or "")[:80], "alert_new": bool(r.get("alert_new", True)),
                      "console_errors": bool(r.get("console_errors", False))}
    return out


def _site_scope(sid) -> dict:
    return {"_id": oid(sid), "workspace_id": g.ws_id, **client_scope()}


def _get_site(sid) -> dict:
    site = get_db().websites.find_one(_site_scope(sid))
    if not site:
        raise ApiError("Website not found", 404)
    return site


def _uptime(site_id, since) -> float | None:
    db = get_db()
    total = db.check_results.count_documents({"website_id": site_id, "kind": "http", "at": {"$gte": since}})
    if not total:
        return None
    ok = db.check_results.count_documents({"website_id": site_id, "kind": "http", "at": {"$gte": since}, "ok": True})
    return round(ok / total * 100, 2)


@bp.get("/websites")
@require()
def list_websites():
    db = get_db()
    q = {"workspace_id": g.ws_id, **client_scope()}
    if request.args.get("client_id"):
        q["client_id"] = maybe_oid(request.args["client_id"])
    if request.args.get("status"):
        q["status"] = request.args["status"]
    if request.args.get("q"):
        import re
        rx = {"$regex": re.escape(request.args["q"]), "$options": "i"}
        q["$or"] = [{"name": rx}, {"url": rx}, {"labels": rx}]
    rows = list(db.websites.find(q).sort("name", 1))
    clients = {c["_id"]: c["name"] for c in db.clients.find({"workspace_id": g.ws_id})}
    since = now() - timedelta(hours=24)
    for s in rows:
        s["client_name"] = clients.get(s.get("client_id"))
        s["uptime_24h"] = _uptime(s["_id"], since)
        s["spark"] = [r.get("response_ms") for r in db.check_results.find(
            {"website_id": s["_id"], "kind": "http"}, {"response_ms": 1}).sort("at", -1).limit(24)][::-1]
    return jsonify(ser(rows))


def _insert_website(data: dict, *, run_initial: bool = True) -> dict:
    require_capacity(g.ws, "websites", "websites", "websites")
    fields = _website_fields(data, g.ws)
    t = now()
    doc = {"workspace_id": g.ws_id, "client_id": None, "paused": False, "status": "unknown", "consecutive_failures": 0,
           "created_at": t, "next_check_at": t, "ssl_next_at": t, "domain_next_at": t, "site_key": token("sg_", 12),
           "ssl_reminder_days": [30, 14, 7, 1], "domain_reminder_days": [60, 30, 14, 7], "environment": "production",
           "rum": {"enabled": True, "sample_rate": 1.0, "capture_api": True, "alert_threshold": 10, "ignore_patterns": [], "release": "", "alert_new": True, "console_errors": False},
           **fields}
    if get_db().websites.find_one({"workspace_id": g.ws_id, "normalized_url": doc["normalized_url"]}):
        raise ApiError("This website is already being monitored in this workspace", 409, "duplicate")
    try:
        doc["_id"] = get_db().websites.insert_one(doc).inserted_id
    except DuplicateKeyError:
        raise ApiError("This website is already being monitored in this workspace", 409, "duplicate")
    audit("website.created", "website", doc["_id"], {"url": doc["url"]})
    if run_initial:
        checks.run_website_check(doc["_id"])
        get_db().websites.update_one({"_id": doc["_id"]}, {"$set": {"next_check_at": now() + timedelta(seconds=doc["interval_sec"])}})
    return get_db().websites.find_one({"_id": doc["_id"]})


@bp.post("/websites")
@require("member")
def create_website():
    data = body()
    return jsonify(ser(_insert_website(data, run_initial=bool(data.get("run_initial_check", True))))), 201


@bp.post("/websites/bulk")
@require("member")
def bulk_create_websites():
    """Import websites from CSV rows or JSON list. Columns: url, name, client, environment, interval_sec, labels."""
    data = body()
    rows = data.get("websites") or data.get("rows") or []
    csv_text = (data.get("csv") or "").strip()
    if csv_text and not rows:
        import csv
        import io
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
    if not rows:
        raise ApiError("Provide csv text or a websites array", 422)
    if len(rows) > 100:
        raise ApiError("Import at most 100 websites at a time", 422)

    clients_by_name = {c["name"].strip().lower(): c["_id"] for c in get_db().clients.find({"workspace_id": g.ws_id}, {"name": 1})}
    created, skipped, errors = [], [], []
    run_checks = bool(data.get("run_initial_check", True))
    for i, raw in enumerate(rows):
        try:
            url = (raw.get("url") or raw.get("URL") or "").strip()
            if not url:
                raise ApiError("url is required", 422)
            client_name = (raw.get("client") or raw.get("client_name") or "").strip()
            client_id = raw.get("client_id")
            if client_name and not client_id:
                client_id = clients_by_name.get(client_name.lower())
                if not client_id:
                    cid = get_db().clients.insert_one({
                        "workspace_id": g.ws_id, "name": client_name[:100], "created_at": now(),
                        "notes": "", "contact_email": "",
                    }).inserted_id
                    clients_by_name[client_name.lower()] = cid
                    client_id = cid
            labels = raw.get("labels") or []
            if isinstance(labels, str):
                labels = [x.strip() for x in labels.split(",") if x.strip()]
            payload = {
                "url": url,
                "name": (raw.get("name") or "").strip(),
                "client_id": str(client_id) if client_id else None,
                "environment": (raw.get("environment") or "production").strip().lower(),
                "interval_sec": int(raw["interval_sec"]) if str(raw.get("interval_sec") or "").isdigit() else None,
                "labels": labels,
            }
            if payload["interval_sec"] is None:
                payload.pop("interval_sec")
            site = _insert_website(payload, run_initial=run_checks)
            created.append(ser(site))
        except ApiError as e:
            msg = e.message
            if e.code == "duplicate":
                skipped.append({"row": i + 1, "url": raw.get("url"), "reason": msg})
            else:
                errors.append({"row": i + 1, "url": raw.get("url"), "error": msg})
        except Exception as e:  # noqa: BLE001
            errors.append({"row": i + 1, "url": raw.get("url"), "error": str(e)})
    return jsonify({"created": created, "skipped": skipped, "errors": errors,
                    "counts": {"created": len(created), "skipped": len(skipped), "errors": len(errors)}}), 201


@bp.get("/websites/<sid>")
@require()
def get_website(sid):
    db = get_db()
    site = _get_site(sid)
    t = now()
    since24 = t - timedelta(hours=24)
    site["uptime"] = {"24h": _uptime(site["_id"], since24), "7d": _uptime(site["_id"], t - timedelta(days=7)),
                      "30d": _uptime(site["_id"], t - timedelta(days=30))}
    site["client_name"] = (db.clients.find_one({"_id": site.get("client_id")}) or {}).get("name")
    site["open_incidents"] = ser(list(db.incidents.find({"website_id": site["_id"], "status": {"$in": ["open", "investigating"]}}).sort("started_at", -1)))
    console_attr = ' data-console-errors="true"' if (site.get("rum") or {}).get("console_errors") else ""
    site["snippet"] = f'<script src="{Config.PUBLIC_API_URL}/sdk.js" data-site-key="{site["site_key"]}"{console_attr} async></script>'
    journeys_failing = db.browser_tests.count_documents({"website_id": site["_id"], "status": "failing"})
    journeys_total = db.browser_tests.count_documents({"website_id": site["_id"]})
    apis_failing = db.api_monitors.count_documents({"website_id": site["_id"], "status": {"$in": ["down", "failing", "degraded"]}})
    apis_total = db.api_monitors.count_documents({"website_id": site["_id"]})
    pages_total = db.page_checks.count_documents({"website_id": site["_id"]})
    pages_failing = db.page_checks.count_documents({"website_id": site["_id"], "status": {"$in": ["failing", "failed", "error"]}})
    visual_pending = db.visual_changes.count_documents({"website_id": site["_id"], "status": "pending_review"})
    errors_active = db.error_groups.count_documents({"website_id": site["_id"], "status": "active"})
    errors_24h = db.error_groups.count_documents({"website_id": site["_id"], "last_seen": {"$gte": since24}})
    http_n = db.check_results.count_documents({"website_id": site["_id"], "kind": "http", "at": {"$gte": since24}})
    http_fail = db.check_results.count_documents({"website_id": site["_id"], "kind": "http", "at": {"$gte": since24}, "ok": False})
    avg = list(db.check_results.aggregate([
        {"$match": {"website_id": site["_id"], "kind": "http", "at": {"$gte": since24}}},
        {"$group": {"_id": None, "avg": {"$avg": "$response_ms"}}},
    ]))
    site["counts"] = {
        "api_monitors": apis_total,
        "page_checks": pages_total,
        "browser_tests": journeys_total,
        "error_groups": errors_active,
    }
    site["insights"] = {
        "checks_24h": http_n,
        "failures_24h": http_fail,
        "avg_response_ms_24h": round(avg[0]["avg"]) if avg and avg[0].get("avg") is not None else None,
        "open_incidents": len(site["open_incidents"]),
        "errors_active": errors_active,
        "errors_24h": errors_24h,
        "journeys_failing": journeys_failing,
        "journeys_total": journeys_total,
        "apis_failing": apis_failing,
        "apis_total": apis_total,
        "page_checks_failing": pages_failing,
        "page_checks_total": pages_total,
        "visual_pending": visual_pending,
        "ssl_days_left": (site.get("ssl") or {}).get("days_left"),
        "domain_days_left": (site.get("domain") or {}).get("days_left"),
    }
    return jsonify(ser(site))


@bp.patch("/websites/<sid>")
@require("member")
def update_website(sid):
    site = _get_site(sid)
    data = body()
    fields = _website_fields(data, g.ws, site)
    if "paused" in data:
        fields["paused"] = bool(data["paused"])
        fields["status"] = "paused" if fields["paused"] else "unknown"
        if not fields["paused"]:
            fields["next_check_at"] = now()
    if fields.get("normalized_url") and fields["normalized_url"] != site["normalized_url"]:
        if get_db().websites.find_one({"workspace_id": g.ws_id, "normalized_url": fields["normalized_url"], "_id": {"$ne": site["_id"]}}):
            raise ApiError("Another website with this URL already exists", 409, "duplicate")
    get_db().websites.update_one({"_id": site["_id"]}, {"$set": fields})
    audit("website.updated", "website", site["_id"], {"fields": list(fields)})
    return jsonify(ser(get_db().websites.find_one({"_id": site["_id"]})))


@bp.delete("/websites/<sid>")
@require("admin")
def delete_website(sid):
    db = get_db()
    site = _get_site(sid)
    for coll in ("check_results", "error_groups", "error_events", "visual_changes", "test_runs", "discoveries"):
        db[coll].delete_many({"website_id": site["_id"]})
    db.api_monitors.update_many({"website_id": site["_id"]}, {"$set": {"website_id": None}})
    db.page_checks.delete_many({"website_id": site["_id"]})
    db.browser_tests.delete_many({"website_id": site["_id"]})
    db.websites.delete_one({"_id": site["_id"]})
    audit("website.deleted", "website", site["_id"], {"url": site["url"]})
    return jsonify({"ok": True})


@bp.post("/websites/<sid>/check")
@require("member")
def check_now(sid):
    site = _get_site(sid)
    kind = request.args.get("kind", "http")
    if kind == "ssl":
        checks.run_ssl_check(site["_id"])
    elif kind == "domain":
        checks.run_domain_check(site["_id"])
    else:
        checks.run_website_check(site["_id"])
    return get_website(sid)


@bp.post("/websites/<sid>/rotate-key")
@require("admin")
def rotate_key(sid):
    site = _get_site(sid)
    get_db().websites.update_one({"_id": site["_id"]}, {"$set": {"site_key": token("sg_", 12)}})
    audit("website.key_rotated", "website", site["_id"])
    return get_website(sid)


@bp.get("/websites/<sid>/results")
@require()
def results(sid):
    site = _get_site(sid)
    kind = request.args.get("kind", "http")
    hours = clamp_int(request.args.get("hours"), 1, 24 * 365, 24)
    q = {"website_id": site["_id"], "kind": kind, "at": {"$gte": now() - timedelta(hours=hours)}}
    if request.args.get("failures") == "1":
        q["ok"] = False
    rows = list(get_db().check_results.find(q).sort("at", -1).limit(clamp_int(request.args.get("limit"), 1, 2000, 500)))
    return jsonify(ser(rows))


@bp.get("/websites/<sid>/stats")
@require()
def stats(sid):
    """Bucketed response-time and availability series for charts."""
    site = _get_site(sid)
    hours = clamp_int(request.args.get("hours"), 1, 24 * 90, 24)
    bucket_min = 5 if hours <= 6 else 15 if hours <= 24 else 60 if hours <= 24 * 7 else 360
    since = now() - timedelta(hours=hours)
    pipeline = [
        {"$match": {"website_id": site["_id"], "kind": "http", "at": {"$gte": since}}},
        {"$group": {"_id": {"$toDate": {"$subtract": [{"$toLong": "$at"}, {"$mod": [{"$toLong": "$at"}, bucket_min * 60000]}]}},
                    "avg": {"$avg": "$response_ms"}, "max": {"$max": "$response_ms"}, "n": {"$sum": 1},
                    "fail": {"$sum": {"$cond": ["$ok", 0, 1]}}, "transient": {"$sum": {"$cond": [{"$eq": ["$classification", "transient"]}, 1, 0]}}}},
        {"$sort": {"_id": 1}},
    ]
    rows = [{"t": r["_id"], "avg_ms": round(r["avg"] or 0), "max_ms": round(r["max"] or 0), "checks": r["n"], "failures": r["fail"],
             "transient": r["transient"], "uptime": round((r["n"] - r["fail"]) / r["n"] * 100, 2)} for r in get_db().check_results.aggregate(pipeline)]
    incidents = list(get_db().incidents.find({"website_id": site["_id"], "started_at": {"$gte": since - timedelta(days=30)}}).sort("started_at", -1).limit(50))
    return jsonify(ser({"series": rows, "bucket_min": bucket_min, "incidents": incidents}))


# ------------------------------------------------------------------ API monitors

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _monitor_fields(data: dict, existing: dict | None = None) -> dict:
    from ..security import encrypt
    out = {}
    if "url" in data or not existing:
        url = normalize_url(data.get("url", ""))
        ok, reason = validate_target(url)
        if not ok:
            raise ApiError(f"This URL cannot be monitored: {reason}", 422)
        out["url"] = url
    if "name" in data or not existing:
        out["name"] = (data.get("name") or "").strip()[:100] or "API check"
    if "method" in data or not existing:
        m = str(data.get("method") or "GET").upper()
        if m not in _METHODS:
            raise ApiError("Unsupported HTTP method", 422)
        out["method"] = m
    if "website_id" in data:
        wid = maybe_oid(data.get("website_id"))
        if wid and not get_db().websites.find_one({"_id": wid, "workspace_id": g.ws_id}):
            raise ApiError("Website not found", 404)
        out["website_id"] = wid
    for k in ("headers", "query"):
        if k in data or not existing:
            v = data.get(k) or {}
            if not isinstance(v, dict):
                raise ApiError(f"{k} must be an object", 422)
            out[k] = {str(a)[:100]: str(b)[:2000] for a, b in v.items() if str(a).strip()}
    if "secret_headers" in data:
        enc = dict((existing or {}).get("secret_headers_enc") or {})
        for k, v in (data.get("secret_headers") or {}).items():
            if v is None or v == "":
                enc.pop(k, None)
            elif v != "••••••":
                enc[str(k)[:100]] = encrypt(str(v))
        out["secret_headers_enc"] = enc
    if "body" in data or not existing:
        out["body"] = str(data.get("body") or "")[:20000]
        out["body_type"] = data.get("body_type") if data.get("body_type") in ("json", "form", "text") else "json"
    if "expected_statuses" in data or not existing:
        codes = [int(c) for c in (data.get("expected_statuses") or []) if str(c).isdigit()]
        out["expected_statuses"] = codes or [200]
    if "assertions" in data or not existing:
        valid = []
        for a in data.get("assertions") or []:
            if a.get("type") in ("json_path", "body_contains", "body_not_contains", "header", "response_time"):
                valid.append({"type": a["type"], "path": str(a.get("path") or "")[:200], "op": a.get("op") or "equals",
                              "value": str(a.get("value") if a.get("value") is not None else "")[:500]})
        out["assertions"] = valid[:20]
    lim = limits(g.ws)
    for k, (lo, hi, d) in {"interval_sec": (lim["min_interval_sec"], 86400, 300), "timeout_sec": (2, 60, 15), "retries": (0, 5, 1),
                           "failure_threshold": (1, 10, 2), "max_response_ms": (0, 60000, 0)}.items():
        if k in data or not existing:
            out[k] = clamp_int(data.get(k), lo, hi, d)
    if "store_body" in data or not existing:
        out["store_body"] = bool(data.get("store_body", False))
    return out


def _monitor_out(m: dict) -> dict:
    out = ser(m)
    out["secret_headers"] = {k: "••••••" for k in (m.get("secret_headers_enc") or {})}
    return out


@bp.get("/api-monitors")
@require()
def list_monitors():
    q = {"workspace_id": g.ws_id}
    if request.args.get("website_id"):
        q["website_id"] = oid(request.args["website_id"])
    rows = list(get_db().api_monitors.find(q).sort("name", 1))
    sites = {s["_id"]: s["name"] for s in get_db().websites.find({"workspace_id": g.ws_id}, {"name": 1})}
    out = []
    for m in rows:
        o = _monitor_out(m)
        o["website_name"] = sites.get(m.get("website_id"))
        out.append(o)
    return jsonify(out)


@bp.post("/api-monitors")
@require("member")
def create_monitor():
    require_capacity(g.ws, "api_monitors", "api_monitors", "API monitors")
    data = body()
    doc = {"workspace_id": g.ws_id, "website_id": None, "paused": False, "status": "unknown", "consecutive_failures": 0,
           "created_at": now(), "next_check_at": now() + timedelta(seconds=5), **_monitor_fields(data)}
    doc["_id"] = get_db().api_monitors.insert_one(doc).inserted_id
    audit("api_monitor.created", "api_monitor", doc["_id"], {"url": doc["url"]})
    return jsonify(_monitor_out(doc)), 201


def _get_monitor(mid):
    m = get_db().api_monitors.find_one({"_id": oid(mid), "workspace_id": g.ws_id})
    if not m:
        raise ApiError("API monitor not found", 404)
    return m


@bp.get("/api-monitors/<mid>")
@require()
def get_monitor(mid):
    m = _get_monitor(mid)
    out = _monitor_out(m)
    out["results"] = ser(list(get_db().check_results.find({"monitor_id": m["_id"]}).sort("at", -1).limit(100)))
    return jsonify(out)


@bp.patch("/api-monitors/<mid>")
@require("member")
def update_monitor(mid):
    m = _get_monitor(mid)
    data = body()
    fields = _monitor_fields(data, m)
    if "paused" in data:
        fields["paused"] = bool(data["paused"])
        fields["status"] = "paused" if fields["paused"] else "unknown"
    get_db().api_monitors.update_one({"_id": m["_id"]}, {"$set": fields})
    audit("api_monitor.updated", "api_monitor", m["_id"], {"fields": [f for f in fields if f != "secret_headers_enc"],
                                                           "secrets_changed": "secret_headers_enc" in fields})
    return jsonify(_monitor_out(get_db().api_monitors.find_one({"_id": m["_id"]})))


@bp.delete("/api-monitors/<mid>")
@require("member")
def delete_monitor(mid):
    m = _get_monitor(mid)
    get_db().api_monitors.delete_one({"_id": m["_id"]})
    get_db().check_results.delete_many({"monitor_id": m["_id"]})
    audit("api_monitor.deleted", "api_monitor", m["_id"])
    return jsonify({"ok": True})


@bp.post("/api-monitors/<mid>/run")
@require("member")
def run_monitor(mid):
    m = _get_monitor(mid)
    res = checks.run_api_check(m["_id"])
    return jsonify(ser(res))


# ------------------------------------------------------------------ import (Postman / OpenAPI / HAR / CSV / cURL)


@bp.post("/api-monitors/import/parse")
@require("member")
def parse_import():
    from ..services import api_import
    data = body()
    content = str(data.get("content") or "")
    if len(content) > 3_000_000:
        raise ApiError("That file is too large (max 3 MB)", 413)
    try:
        out = api_import.parse(content, str(data.get("format") or "auto"))
    except ValueError as e:
        raise ApiError(str(e), 422) from e
    existing = {(m["method"], m["url"].split("?")[0].rstrip("/"))
                for m in get_db().api_monitors.find({"workspace_id": g.ws_id}, {"method": 1, "url": 1})}
    for i, it in enumerate(out["items"]):
        it["key"] = str(i)
        it["exists"] = (it["method"], it["url"].split("?")[0].rstrip("/")) in existing
    return jsonify(out)


@bp.post("/api-monitors/import")
@require("member")
def run_import():
    from ..services import api_import
    data = body()
    items = data.get("items") or []
    if not isinstance(items, list) or not items:
        raise ApiError("Pick at least one API to import", 422)
    variables = {str(k): str(v) for k, v in (data.get("variables") or {}).items()}
    db = get_db()
    sites = list(db.websites.find({"workspace_id": g.ws_id}, {"name": 1, "url": 1}))
    default_site = maybe_oid(data.get("website_id"))
    created, skipped, failed = [], [], []
    for raw in items[:200]:
        it = api_import.apply_variables(raw, variables)
        label = it.get("name") or it.get("url")
        missing = api_import.VAR.findall(it.get("url", ""))
        if missing:
            failed.append({"name": label, "row": it.get("row"), "error": f"Fill in a value for {{{{{missing[0]}}}}}"})
            continue
        site_id = default_site
        if it.get("website"):
            w = it["website"].lower()
            match = next((s for s in sites if s["name"].lower() == w or w in s["url"].lower()), None)
            site_id = match["_id"] if match else site_id
        payload = {k: it[k] for k in ("name", "method", "url", "headers", "secret_headers", "body", "body_type", "expected_statuses",
                                      "assertions", "max_response_ms", "interval_sec", "query") if k in it}
        if "interval_sec" not in payload and data.get("interval_sec"):
            payload["interval_sec"] = data["interval_sec"]
        payload["website_id"] = str(site_id) if site_id else None
        try:
            fields = _monitor_fields(payload)
            if db.api_monitors.find_one({"workspace_id": g.ws_id, "method": fields["method"], "url": fields["url"]}):
                skipped.append({"name": label, "row": it.get("row"), "reason": "Already monitored"})
                continue
            require_capacity(g.ws, "api_monitors", "api_monitors", "API monitors")
        except ApiError as e:
            failed.append({"name": label, "row": it.get("row"), "error": e.message if hasattr(e, "message") else str(e)})
            if getattr(e, "code", "") == "plan_limit":
                break
            continue
        doc = {"workspace_id": g.ws_id, "website_id": None, "paused": False, "status": "unknown", "consecutive_failures": 0,
               "created_at": now(), "next_check_at": now() + timedelta(seconds=5), "imported": True, **fields}
        doc["_id"] = db.api_monitors.insert_one(doc).inserted_id
        created.append(_monitor_out(doc))
    audit("api_monitor.imported", "workspace", g.ws_id, {"created": len(created), "skipped": len(skipped), "failed": len(failed)})
    return jsonify({"created": created, "skipped": skipped, "failed": failed}), 201


# ------------------------------------------------------------------ endpoint discovery


def _discovery_out(d: dict | None) -> dict | None:
    if not d:
        return None
    out = ser(d)
    added = set(d.get("added") or [])
    monitored = {(m["method"], m["url"].split("?")[0].rstrip("/"))
                 for m in get_db().api_monitors.find({"workspace_id": d["workspace_id"]}, {"method": 1, "url": 1})}
    for ep in out.get("endpoints") or []:
        ep["added"] = ep["key"] in added or (ep["method"], ep["url"].rstrip("/")) in monitored
    return out


@bp.post("/websites/<sid>/discover")
@require("member")
def start_discovery(sid):
    from ..services import discovery
    site = _get_site(sid)
    doc = discovery.start_discovery(g.ws, site, g.user["_id"])
    audit("website.discovery_started", "website", site["_id"])
    return jsonify(_discovery_out(doc)), 202


@bp.get("/discoveries")
@require()
def list_discoveries():
    """Latest scan per website, so the API monitors page can show found endpoints."""
    db = get_db()
    sites = list(db.websites.find({"workspace_id": g.ws_id, **client_scope()}, {"name": 1, "url": 1}))
    rows = []
    for site in sites:
        d = db.discoveries.find_one({"workspace_id": g.ws_id, "website_id": site["_id"]}, sort=[("started_at", -1)])
        if not d:
            continue
        found = d.get("endpoints_found")
        if found is None:
            found = len(d.get("endpoints") or [])
        if d.get("status") != "running" and not found:
            continue
        rows.append({
            "id": d["_id"], "website_id": site["_id"], "website_name": site.get("name"), "website_url": site.get("url"),
            "status": d.get("status"), "endpoints_found": found,
            "finished_at": d.get("finished_at"), "started_at": d.get("started_at"),
        })
    rows.sort(key=lambda r: r.get("finished_at") or r.get("started_at") or now(), reverse=True)
    return jsonify(ser(rows))


@bp.get("/websites/<sid>/discovery")
@require()
def latest_discovery(sid):
    site = _get_site(sid)
    d = get_db().discoveries.find_one({"website_id": site["_id"], "workspace_id": g.ws_id}, sort=[("started_at", -1)])
    return jsonify(_discovery_out(d))


@bp.post("/websites/<sid>/discovery/<did>/monitors")
@require("member")
def add_discovered_monitors(sid, did):
    """Create API monitors from discovered endpoints, optionally with per-endpoint overrides."""
    site = _get_site(sid)
    db = get_db()
    d = db.discoveries.find_one({"_id": oid(did), "website_id": site["_id"], "workspace_id": g.ws_id})
    if not d:
        raise ApiError("Discovery not found", 404)
    by_key = {e["key"]: e for e in d.get("endpoints") or []}
    items = body().get("items") or []
    if not isinstance(items, list) or not items:
        raise ApiError("Select at least one endpoint", 422)
    created, skipped = [], []
    for item in items[:50]:
        ep = by_key.get(item.get("key"))
        if not ep:
            skipped.append({"key": item.get("key"), "reason": "not in this discovery"})
            continue
        if db.api_monitors.find_one({"workspace_id": g.ws_id, "method": ep["method"], "url": normalize_url(item.get("url") or ep["url"])}):
            skipped.append({"key": ep["key"], "reason": "already monitored"})
            continue
        require_capacity(g.ws, "api_monitors", "api_monitors", "API monitors")
        hint = (ep.get("name_hint") or "").strip()
        data = {"name": (hint or f"{ep['method']} {ep['path']}")[:100], "method": ep["method"], "url": ep["url"], "query": ep.get("query") or {},
                "website_id": str(site["_id"]), **ep.get("suggested", {}), **{k: v for k, v in item.items() if k != "key"}}
        doc = {"workspace_id": g.ws_id, "website_id": None, "paused": False, "status": "unknown", "consecutive_failures": 0,
               "created_at": now(), "next_check_at": now() + timedelta(seconds=5), "discovered": True, **_monitor_fields(data)}
        doc["_id"] = db.api_monitors.insert_one(doc).inserted_id
        audit("api_monitor.created", "api_monitor", doc["_id"], {"url": doc["url"], "source": "discovery"})
        created.append(_monitor_out(doc))
        db.discoveries.update_one({"_id": d["_id"]}, {"$addToSet": {"added": ep["key"]}})
    return jsonify({"created": created, "skipped": skipped}), 201
