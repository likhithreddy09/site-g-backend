import os
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..audit import audit
from ..db import get_db
from ..plans import limits, quota_left, require_capacity
from ..security import normalize_url, require, sign_artifact, validate_target
from ..services import artifacts, browser, incidents, page_preview
from ..utils import ApiError, clamp_int, maybe_oid, now, oid, ser
from . import body

bp = Blueprint("testing", __name__, url_prefix="/api")


def _sign_visual(v: dict | None) -> dict | None:
    if not v:
        return v
    return {**v, **{f"{k}_url": sign_artifact(v.get(k)) for k in ("screenshot", "baseline", "diff") if v.get(k)}}


def _check_site(wid):
    wid = maybe_oid(wid)
    if wid and not get_db().websites.find_one({"_id": wid, "workspace_id": g.ws_id}):
        raise ApiError("Website not found", 404)
    return wid


# ------------------------------------------------------------------ page checks (content + visual + links)


def _page_fields(data: dict, existing: dict | None = None) -> dict:
    out = {}
    if "url" in data or not existing:
        url = normalize_url(data.get("url", ""))
        ok, reason = validate_target(url)
        if not ok:
            raise ApiError(f"This URL cannot be checked: {reason}", 422)
        out["url"] = url
    if "name" in data or not existing:
        out["name"] = (data.get("name") or "").strip()[:100] or "Page check"
    if "website_id" in data or not existing:
        out["website_id"] = _check_site(data.get("website_id"))
    for k in ("expected_texts", "required_selectors", "ignore_selectors"):
        if k in data or not existing:
            v = data.get(k) or []
            if isinstance(v, str):
                v = [x.strip() for x in v.split("\n")]
            out[k] = [str(x)[:300] for x in v if str(x).strip()][:30]
    if "element_labels" in data or not existing:
        labels = data.get("element_labels") or {}
        out["element_labels"] = {str(k)[:300]: str(v)[:80] for k, v in (labels.items() if isinstance(labels, dict) else []) if str(v).strip()}
    if "ignore_labels" in data or not existing:
        labels = data.get("ignore_labels") or {}
        out["ignore_labels"] = {str(k)[:300]: str(v)[:80] for k, v in (labels.items() if isinstance(labels, dict) else []) if str(v).strip()}
    if "ignore_regions" in data or not existing:
        out["ignore_regions"] = [{k: clamp_int(r.get(k), 0, 10000, 0) for k in ("x", "y", "w", "h")} for r in data.get("ignore_regions") or []][:20]
    if "threshold_pct" in data or not existing:
        try:
            out["threshold_pct"] = max(0.01, min(50.0, float(data.get("threshold_pct", 1.0))))
        except (TypeError, ValueError):
            out["threshold_pct"] = 1.0
    if "interval_sec" in data or not existing:
        out["interval_sec"] = clamp_int(data.get("interval_sec"), 300, 7 * 86400, 3600)
    for k, d in (("visual_enabled", True), ("check_links", False)):
        if k in data or not existing:
            out[k] = bool(data.get(k, d))
    return out


def _get_page_check(cid):
    c = get_db().page_checks.find_one({"_id": oid(cid), "workspace_id": g.ws_id})
    if not c:
        raise ApiError("Check not found", 404)
    return c


def _page_out(c: dict) -> dict:
    o = ser(c)
    o["baseline_url"] = sign_artifact((c.get("baseline") or {}).get("path"))
    o["last_screenshot_url"] = sign_artifact(c.get("last_screenshot"))
    return o


@bp.get("/page-checks")
@require()
def list_page_checks():
    q = {"workspace_id": g.ws_id}
    if request.args.get("website_id"):
        q["website_id"] = oid(request.args["website_id"])
    sites = {s["_id"]: s["name"] for s in get_db().websites.find({"workspace_id": g.ws_id}, {"name": 1})}
    out = []
    for c in get_db().page_checks.find(q).sort("name", 1):
        o = _page_out(c)
        o["website_name"] = sites.get(c.get("website_id"))
        o["pending_changes"] = get_db().visual_changes.count_documents({"page_check_id": c["_id"], "status": "pending_review"})
        out.append(o)
    return jsonify(out)


@bp.post("/page-checks")
@require("member")
def create_page_check():
    require_capacity(g.ws, "content_checks", "page_checks", "content checks")
    doc = {"workspace_id": g.ws_id, "paused": False, "status": "pending", "baseline": None, "created_at": now(),
           "next_check_at": now() + timedelta(seconds=10), **_page_fields(body())}
    doc["_id"] = get_db().page_checks.insert_one(doc).inserted_id
    audit("page_check.created", "page_check", doc["_id"], {"url": doc["url"]})
    return jsonify(_page_out(doc)), 201


@bp.post("/page-checks/preview")
@require("member")
def preview_page():
    if quota_left(g.ws, "browser_seconds", "browser_minutes", 60) <= 0:
        raise ApiError("Browser minutes for this month are used up", 402, "plan_limit")
    return jsonify(page_preview.preview(g.ws, normalize_url(body().get("url", ""))))


@bp.get("/page-checks/<cid>")
@require()
def get_page_check(cid):
    c = _get_page_check(cid)
    db = get_db()
    o = _page_out(c)
    res = []
    for r in db.check_results.find({"page_check_id": c["_id"]}).sort("at", -1).limit(30):
        r = ser(r)
        r["details"]["visual"] = _sign_visual(r["details"].get("visual"))
        res.append(r)
    o["results"] = res
    o["changes"] = [_sign_visual(ser(x)) for x in db.visual_changes.find({"page_check_id": c["_id"]}).sort("at", -1).limit(50)]
    return jsonify(o)


@bp.patch("/page-checks/<cid>")
@require("member")
def update_page_check(cid):
    c = _get_page_check(cid)
    data = body()
    fields = _page_fields(data, c)
    if "paused" in data:
        fields["paused"] = bool(data["paused"])
    if "url" in fields and fields["url"] != c["url"]:
        fields["baseline"] = None
    get_db().page_checks.update_one({"_id": c["_id"]}, {"$set": fields})
    return jsonify(_page_out(get_db().page_checks.find_one({"_id": c["_id"]})))


@bp.delete("/page-checks/<cid>")
@require("member")
def delete_page_check(cid):
    c = _get_page_check(cid)
    get_db().page_checks.delete_one({"_id": c["_id"]})
    get_db().visual_changes.delete_many({"page_check_id": c["_id"]})
    audit("page_check.deleted", "page_check", c["_id"])
    return jsonify({"ok": True})


@bp.post("/page-checks/<cid>/run")
@require("member")
def run_page_check(cid):
    c = _get_page_check(cid)
    browser.run_page_check(c["_id"])
    return get_page_check(cid)


@bp.post("/page-checks/<cid>/baseline")
@require("member")
def approve_baseline(cid):
    """Approve a screenshot (latest or from a change) as the new baseline."""
    c = _get_page_check(cid)
    db = get_db()
    change_id = body().get("change_id")
    src = None
    if change_id:
        ch = db.visual_changes.find_one({"_id": oid(change_id), "page_check_id": c["_id"]})
        if not ch:
            raise ApiError("Change not found", 404)
        src = ch["screenshot"]
        db.visual_changes.update_one({"_id": ch["_id"]}, {"$set": {"status": "approved", "reviewed_by": g.user["email"], "reviewed_at": now()}})
    else:
        src = c.get("last_screenshot")
    if not src:
        raise ApiError("No screenshot available yet — run the check first", 409)
    if not artifacts.exists(src):
        raise ApiError("Screenshot file is missing — re-run the check to capture a new one", 409)
    dst_rel = f"{g.ws_id}/baseline-{int(now().timestamp())}-{os.path.basename(src)}"
    try:
        artifacts.copy(src, dst_rel)
    except FileNotFoundError as e:
        raise ApiError("Screenshot file is missing — re-run the check to capture a new one", 409) from e
    db.page_checks.update_one({"_id": c["_id"]}, {"$set": {"baseline": {"path": dst_rel, "at": now(),
                                                                         "approved_by": g.user["email"]}, "status": "passing"}})
    db.visual_changes.update_many({"page_check_id": c["_id"], "status": "pending_review"}, {"$set": {"status": "superseded"}})
    audit("page_check.baseline_approved", "page_check", c["_id"])
    return get_page_check(cid)


@bp.post("/visual-changes/<chid>/review")
@require("member")
def review_change(chid):
    db = get_db()
    ch = db.visual_changes.find_one({"_id": oid(chid), "workspace_id": g.ws_id})
    if not ch:
        raise ApiError("Change not found", 404)
    decision = body().get("decision")
    if decision == "issue":
        chk = db.page_checks.find_one({"_id": ch["page_check_id"]})
        site = db.websites.find_one({"_id": ch.get("website_id")}) if ch.get("website_id") else None
        inc = incidents.open_or_update(g.ws, key=f"visual:{ch['_id']}", source_type="page_check", source_id=ch["page_check_id"],
                                       website_id=ch.get("website_id"), client_id=(site or {}).get("client_id"), severity="major",
                                       title=f"Unintended visual change: {chk['name'] if chk else ch['url']}",
                                       summary=f"{ch['diff_pct']}% of the page changed; flagged as an issue by {g.user['email']}.",
                                       evidence={"type": "visual_change", "ref_id": ch["_id"], "summary": f"{ch['diff_pct']}% visual difference",
                                                 "artifact": ch.get("diff")})
        db.visual_changes.update_one({"_id": ch["_id"]}, {"$set": {"status": "issue", "incident_id": inc["_id"], "reviewed_by": g.user["email"]}})
    elif decision == "dismiss":
        db.visual_changes.update_one({"_id": ch["_id"]}, {"$set": {"status": "dismissed", "reviewed_by": g.user["email"]}})
    else:
        raise ApiError("decision must be 'issue' or 'dismiss'", 422)
    return jsonify({"ok": True})


@bp.get("/visual-changes")
@require()
def list_changes():
    q = {"workspace_id": g.ws_id}
    if request.args.get("status"):
        q["status"] = request.args["status"]
    return jsonify([_sign_visual(ser(x)) for x in get_db().visual_changes.find(q).sort("at", -1).limit(100)])


# ------------------------------------------------------------------ browser tests


def _test_fields(data: dict, existing: dict | None = None) -> dict:
    out = {}
    if "start_url" in data or not existing:
        url = normalize_url(data.get("start_url", ""))
        ok, reason = validate_target(url)
        if not ok:
            raise ApiError(f"This URL cannot be tested: {reason}", 422)
        out["start_url"] = url
    if "name" in data or not existing:
        out["name"] = (data.get("name") or "").strip()[:100] or "User journey"
    if "website_id" in data or not existing:
        out["website_id"] = _check_site(data.get("website_id"))
    if "steps" in data or not existing:
        steps = []
        for s in data.get("steps") or []:
            a = s.get("action")
            if a not in browser.STEP_ACTIONS:
                raise ApiError(f"Unknown step action '{a}'", 422)
            if a in ("click", "fill", "select", "check", "wait_for", "assert_visible", "assert_not_visible") and not s.get("selector"):
                raise ApiError(f"Step '{a}' requires a selector", 422)
            if a in ("fill", "select", "assert_url") and s.get("value") in (None, ""):
                raise ApiError(f"Step '{a}' requires a value", 422)
            steps.append({"action": a, "selector": str(s.get("selector") or "")[:500], "value": str(s.get("value") or "")[:2000],
                          "url": str(s.get("url") or "")[:1000], "description": str(s.get("description") or "")[:200],
                          "timeout_ms": clamp_int(s.get("timeout_ms"), 500, 60000, 15000), "secret": bool(s.get("secret")),
                          "label": str(s.get("label") or "")[:60], "kind": str(s.get("kind") or "")[:20]})
        if len(steps) > 50:
            raise ApiError("A journey can have at most 50 steps", 422)
        out["steps"] = steps
    for k, (lo, hi, d) in {"interval_sec": (300, 7 * 86400, 3600), "timeout_sec": (10, 300, 90), "retries": (0, 3, 1),
                           "failure_threshold": (1, 10, 1)}.items():
        if k in data or not existing:
            out[k] = clamp_int(data.get(k), lo, hi, d)
    if "severity" in data or not existing:
        out["severity"] = data.get("severity") if data.get("severity") in ("minor", "major", "critical") else "major"
    if "safety" in data or not existing:
        s = data.get("safety") or {}
        out["safety"] = {"test_mode_confirmed": bool(s.get("test_mode_confirmed")), "allow_payments": bool(s.get("allow_payments")),
                         "blocked_patterns": [str(x)[:300] for x in s.get("blocked_patterns") or [] if str(x).strip()][:30],
                         "cleanup_notes": str(s.get("cleanup_notes") or "")[:1000]}
    return out


def _get_test(tid):
    t = get_db().browser_tests.find_one({"_id": oid(tid), "workspace_id": g.ws_id})
    if not t:
        raise ApiError("Test not found", 404)
    return t


def _run_out(r: dict) -> dict:
    o = ser(r)
    o["screenshot_url"] = sign_artifact(r.get("screenshot"))
    for s in o.get("steps") or []:
        if s.get("screenshot"):
            s["screenshot_url"] = sign_artifact(s["screenshot"])
    return o


def _assert_safe(test: dict):
    if browser.requires_safety_confirmation(test) and not (test.get("safety") or {}).get("test_mode_confirmed"):
        raise ApiError("This journey fills and submits a form. Confirm it targets a test mode, test inbox, or has cleanup configured before running.",
                       409, "safety_confirmation_required")


@bp.get("/browser-tests")
@require()
def list_tests():
    q = {"workspace_id": g.ws_id}
    if request.args.get("website_id"):
        q["website_id"] = oid(request.args["website_id"])
    sites = {s["_id"]: s["name"] for s in get_db().websites.find({"workspace_id": g.ws_id}, {"name": 1})}
    out = []
    for t in get_db().browser_tests.find(q).sort("name", 1):
        o = ser(t)
        o["website_name"] = sites.get(t.get("website_id"))
        o["recent"] = [{"ok": r["ok"], "at": r["at"].isoformat(), "classification": r.get("classification")}
                       for r in get_db().test_runs.find({"test_id": t["_id"]}, {"ok": 1, "at": 1, "classification": 1}).sort("at", -1).limit(20)][::-1]
        out.append(o)
    lim = limits(g.ws)
    return jsonify({"tests": out, "quota": {"minutes": lim["browser_minutes"],
                                            "used_minutes": round(lim["browser_minutes"] - quota_left(g.ws, "browser_seconds", "browser_minutes", 60) / 60, 2)}})


@bp.post("/browser-tests")
@require("member")
def create_test():
    require_capacity(g.ws, "browser_tests", "browser_tests", "browser tests")
    data = body()
    fields = _test_fields(data)
    doc = {"workspace_id": g.ws_id, "paused": True, "status": "draft", "consecutive_failures": 0, "created_at": now(),
           "next_check_at": now() + timedelta(seconds=fields["interval_sec"]), **fields}
    if data.get("schedule_enabled"):
        _assert_safe(doc)
        doc["paused"] = False
    doc["_id"] = get_db().browser_tests.insert_one(doc).inserted_id
    audit("browser_test.created", "browser_test", doc["_id"], {"start_url": doc["start_url"]})
    return jsonify(ser(doc)), 201


@bp.get("/browser-tests/<tid>")
@require()
def get_test(tid):
    t = _get_test(tid)
    o = ser(t)
    o["runs"] = [_run_out(r) for r in get_db().test_runs.find({"test_id": t["_id"]}).sort("at", -1).limit(30)]
    o["requires_safety_confirmation"] = browser.requires_safety_confirmation(t)
    return jsonify(o)


@bp.patch("/browser-tests/<tid>")
@require("member")
def update_test(tid):
    t = _get_test(tid)
    data = body()
    fields = _test_fields(data, t)
    merged = {**t, **fields}
    if "paused" in data:
        if not data["paused"]:
            _assert_safe(merged)
            fields["next_check_at"] = now() + timedelta(seconds=10)
            if t.get("status") == "draft":
                fields["status"] = "scheduled"
        fields["paused"] = bool(data["paused"])
    get_db().browser_tests.update_one({"_id": t["_id"]}, {"$set": fields})
    audit("browser_test.updated", "browser_test", t["_id"], {"fields": list(fields)})
    return get_test(tid)


@bp.delete("/browser-tests/<tid>")
@require("member")
def delete_test(tid):
    t = _get_test(tid)
    get_db().browser_tests.delete_one({"_id": t["_id"]})
    get_db().test_runs.delete_many({"test_id": t["_id"]})
    audit("browser_test.deleted", "browser_test", t["_id"])
    return jsonify({"ok": True})


@bp.post("/browser-tests/<tid>/run")
@require("member")
def run_test(tid):
    t = _get_test(tid)
    _assert_safe(t)
    run = browser.run_browser_test(t["_id"], trigger=f"manual:{g.user['email']}")
    return jsonify(_run_out(run))


@bp.get("/test-runs/<rid>")
@require()
def get_run(rid):
    r = get_db().test_runs.find_one({"_id": oid(rid), "workspace_id": g.ws_id})
    if not r:
        raise ApiError("Run not found", 404)
    return jsonify(_run_out(r))
