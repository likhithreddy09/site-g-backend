from datetime import timedelta

from .db import get_db
from .utils import ApiError, aware, now

# India-first pricing (INR / month via Cashfree).
# Starter 1–3 sites ₹999 · Growth 4–10 sites ₹2,499 · Agency 10+ ₹4,999 · Enterprise custom
# New workspaces get a 24h trial on the Growth plan; after that the dashboard locks until they pay.
TRIAL_HOURS = 24
TRIAL_PLAN = "agency"  # Growth — full product experience during trial
PAID_PLANS = {"starter", "agency", "agency_pro", "enterprise"}

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


def trial_ends_at(ws: dict):
    return aware(ws.get("trial_ends_at"))


def access(ws: dict) -> dict:
    """Trial / lock state for API + UI.

    - trial_active: within 24h window — full Growth limits
    - locked: trial ended, no paid plan — read-only dashboard
    - open: paid (or legacy workspace without a trial_ends_at)
    """
    plan = ws.get("plan") or DEFAULT_PLAN
    ends = trial_ends_at(ws)
    paid = plan in PAID_PLANS and not ws.get("trial")
    if paid:
        return {
            "status": "open",
            "trial": False,
            "trial_active": False,
            "locked": False,
            "trial_ends_at": ends.isoformat() if ends else None,
            "seconds_left": 0,
            "trial_hours": TRIAL_HOURS,
            "effective_plan": plan,
        }
    if ends:
        left = int((ends - now()).total_seconds())
        if left > 0:
            return {
                "status": "trial_active",
                "trial": True,
                "trial_active": True,
                "locked": False,
                "trial_ends_at": ends.isoformat(),
                "seconds_left": left,
                "trial_hours": TRIAL_HOURS,
                "effective_plan": TRIAL_PLAN,
            }
        return {
            "status": "locked",
            "trial": True,
            "trial_active": False,
            "locked": True,
            "trial_ends_at": ends.isoformat(),
            "seconds_left": 0,
            "trial_hours": TRIAL_HOURS,
            "effective_plan": "free",
        }
    # Legacy workspaces (no trial_ends_at) stay open
    return {
        "status": "open",
        "trial": bool(ws.get("trial")),
        "trial_active": False,
        "locked": False,
        "trial_ends_at": None,
        "seconds_left": 0,
        "trial_hours": TRIAL_HOURS,
        "effective_plan": plan,
    }


def is_locked(ws: dict) -> bool:
    return bool(access(ws)["locked"])


def require_unlocked(ws: dict):
    if is_locked(ws):
        raise ApiError(
            "Your 24-hour free trial has ended. Choose a plan to unlock monitoring.",
            402,
            "trial_locked",
        )


def effective_plan_id(ws: dict) -> str:
    return access(ws)["effective_plan"]


def limits(ws: dict) -> dict:
    pid = effective_plan_id(ws)
    return PLANS.get(pid, PLANS[DEFAULT_PLAN])


def feature(ws: dict, key: str):
    return limits(ws).get(key)


def require_feature(ws: dict, key: str, label: str):
    require_unlocked(ws)
    if not feature(ws, key):
        raise ApiError(f"{label} is not included in your {limits(ws)['name']} plan", 402, "plan_limit")


def require_capacity(ws: dict, key: str, collection: str, label: str):
    require_unlocked(ws)
    cap = limits(ws).get(key, 0)
    count = get_db()[collection].count_documents({"workspace_id": ws["_id"]})
    if count >= cap:
        raise ApiError(f"Your {limits(ws)['name']} plan allows {cap} {label}. Upgrade to add more.", 402, "plan_limit")


def new_trial_fields() -> dict:
    started = now()
    return {
        "plan": TRIAL_PLAN,
        "trial": True,
        "trial_started_at": started,
        "trial_ends_at": started + timedelta(hours=TRIAL_HOURS),
    }


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
