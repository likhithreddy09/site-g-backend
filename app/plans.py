from .db import get_db
from .utils import ApiError, now

# price = display USD; price_inr = Cashfree charge amount (INR / month)
PLANS = {
    "free": {
        "name": "Free", "price": 0, "price_inr": 0, "websites": 3, "min_interval_sec": 300, "history_days": 7,
        "ssl": False, "content_checks": 0, "api_monitors": 0, "browser_tests": 0, "browser_minutes": 0,
        "js_monitoring": False, "team_members": 1, "reports": False, "scheduled_reports": False,
        "white_label": False, "ai_calls": 0, "slack": False, "ingest_events": 0,
    },
    "starter": {
        "name": "Starter", "price": 19, "price_inr": 1499, "websites": 10, "min_interval_sec": 60, "history_days": 30,
        "ssl": True, "content_checks": 10, "api_monitors": 2, "browser_tests": 0, "browser_minutes": 0,
        "js_monitoring": False, "team_members": 1, "reports": True, "scheduled_reports": False,
        "white_label": False, "ai_calls": 0, "slack": False, "ingest_events": 0,
    },
    "agency": {
        "name": "Agency", "price": 79, "price_inr": 6499, "websites": 50, "min_interval_sec": 60, "history_days": 90,
        "ssl": True, "content_checks": 100, "api_monitors": 25, "browser_tests": 25, "browser_minutes": 300,
        "js_monitoring": True, "team_members": 5, "reports": True, "scheduled_reports": True,
        "white_label": False, "ai_calls": 100, "slack": True, "ingest_events": 100_000,
    },
    "agency_pro": {
        "name": "Agency Pro", "price": 199, "price_inr": 16499, "websites": 200, "min_interval_sec": 30, "history_days": 365,
        "ssl": True, "content_checks": 500, "api_monitors": 100, "browser_tests": 100, "browser_minutes": 1500,
        "js_monitoring": True, "team_members": 20, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 500, "slack": True, "ingest_events": 1_000_000,
    },
    "enterprise": {
        "name": "Enterprise", "price": None, "price_inr": None, "websites": 5000, "min_interval_sec": 30, "history_days": 730,
        "ssl": True, "content_checks": 5000, "api_monitors": 2000, "browser_tests": 1000, "browser_minutes": 20000,
        "js_monitoring": True, "team_members": 500, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 5000, "slack": True, "ingest_events": 20_000_000,
    },
}

DEFAULT_PLAN = "agency"


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
