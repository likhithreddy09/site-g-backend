from .db import get_db
from .utils import ApiError, now

# India-first pricing (INR / month via Cashfree).
# Starter 1–3 sites ₹999 · Growth 4–10 sites ₹2,499 · Agency 10+ ₹4,999 · Enterprise custom
PLANS = {
    "free": {
        "name": "Free", "price": 0, "price_inr": 0, "websites": 1, "min_interval_sec": 300, "history_days": 7,
        "ssl": False, "content_checks": 0, "api_monitors": 0, "browser_tests": 0, "browser_minutes": 0,
        "js_monitoring": False, "team_members": 1, "reports": False, "scheduled_reports": False,
        "white_label": False, "ai_calls": 0, "slack": False, "ingest_events": 0,
    },
    "starter": {
        "name": "Starter", "price": 12, "price_inr": 999, "websites": 3, "min_interval_sec": 60, "history_days": 30,
        "ssl": True, "content_checks": 10, "api_monitors": 2, "browser_tests": 0, "browser_minutes": 30,
        "js_monitoring": False, "team_members": 1, "reports": True, "scheduled_reports": False,
        "white_label": False, "ai_calls": 20, "slack": False, "ingest_events": 10_000,
    },
    "agency": {
        "name": "Growth", "price": 30, "price_inr": 2499, "websites": 10, "min_interval_sec": 60, "history_days": 90,
        "ssl": True, "content_checks": 50, "api_monitors": 10, "browser_tests": 10, "browser_minutes": 120,
        "js_monitoring": True, "team_members": 3, "reports": True, "scheduled_reports": True,
        "white_label": False, "ai_calls": 50, "slack": True, "ingest_events": 50_000,
    },
    "agency_pro": {
        "name": "Agency", "price": 60, "price_inr": 4999, "websites": 50, "min_interval_sec": 60, "history_days": 180,
        "ssl": True, "content_checks": 200, "api_monitors": 40, "browser_tests": 40, "browser_minutes": 400,
        "js_monitoring": True, "team_members": 10, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 200, "slack": True, "ingest_events": 250_000,
    },
    "enterprise": {
        "name": "Enterprise", "price": None, "price_inr": None, "websites": 5000, "min_interval_sec": 30, "history_days": 730,
        "ssl": True, "content_checks": 5000, "api_monitors": 2000, "browser_tests": 1000, "browser_minutes": 20000,
        "js_monitoring": True, "team_members": 500, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 5000, "slack": True, "ingest_events": 20_000_000,
    },
}

DEFAULT_PLAN = "free"


def limits(ws: dict) -> dict:
    return PLANS.get(ws.get("plan", DEFAULT_PLAN), PLANS[DEFAULT_PLAN])


def feature(ws: dict, key: str):
    return limits(ws).get(key)


def require_feature(ws: dict, key: str, label: str):
    if not feature(ws, key):
        raise ApiError(f"{label} is not included in your {limits(ws)['name']} plan", 402, "plan_limit")


def require_capacity(ws: dict, key: str, collection: str, label: str):
    cap = limits(ws).get(key, 0)
    count = get_db()[collection].count_documents({"workspace_id": ws["_id"]})
    if count >= cap:
        raise ApiError(f"Your {limits(ws)['name']} plan allows {cap} {label}. Upgrade to add more.", 402, "plan_limit")


def month_key() -> str:
    return now().strftime("%Y-%m")


def usage(ws: dict) -> dict:
    u = ws.get("usage") or {}
    if u.get("month") != month_key():
        return {"month": month_key(), "browser_seconds": 0, "ai_calls": 0, "ingest_events": 0}
    return {"month": u["month"], "browser_seconds": u.get("browser_seconds", 0),
            "ai_calls": u.get("ai_calls", 0), "ingest_events": u.get("ingest_events", 0)}


def add_usage(ws_id, field: str, amount: float) -> None:
    db = get_db()
    mk = month_key()
    res = db.workspaces.update_one({"_id": ws_id, "usage.month": mk}, {"$inc": {f"usage.{field}": amount}})
    if res.matched_count == 0:
        db.workspaces.update_one(
            {"_id": ws_id},
            {"$set": {"usage": {"month": mk, "browser_seconds": 0, "ai_calls": 0, "ingest_events": 0, field: amount}}},
        )


def quota_left(ws: dict, field: str, plan_key: str, factor: float = 1) -> float:
    return limits(ws).get(plan_key, 0) * factor - usage(ws).get(field, 0)
