from datetime import timedelta

from .db import get_db
from .utils import ApiError, aware, now

# India-first pricing (INR / month via Dodo Payments).
# Starter 1–3 sites ₹999 · Growth 4–10 sites ₹2,499 · Agency 10+ ₹4,999 · Enterprise custom
# New workspaces get a 24h trial on the Growth plan; after that the dashboard locks until they pay.
# Each successful Dodo payment unlocks the chosen plan for BILLING_PERIOD_DAYS; then locks again until renewed.
TRIAL_HOURS = 24
TRIAL_PLAN = "agency"  # Growth — full product experience during trial
BILLING_PERIOD_DAYS = 30
PAID_PLANS = {"starter", "agency", "agency_pro", "enterprise"}

PLANS = {
    "free": {
        "name": "Free", "price": 0, "price_inr": 0, "websites": 1, "min_interval_sec": 300, "history_days": 7,
        "ssl": False, "seo_audit": False, "seo_pages": 0, "content_checks": 0, "api_monitors": 0, "browser_tests": 0, "browser_minutes": 0,
        "js_monitoring": False, "team_members": 1, "reports": False, "scheduled_reports": False,
        "white_label": False, "ai_calls": 0, "slack": False, "ingest_events": 0,
    },
    "starter": {
        "name": "Starter", "price": 12, "price_inr": 999, "websites": 3, "min_interval_sec": 60, "history_days": 30,
        "ssl": True, "seo_audit": True, "seo_pages": 10, "content_checks": 10, "api_monitors": 2, "browser_tests": 0, "browser_minutes": 30,
        "js_monitoring": False, "team_members": 1, "reports": True, "scheduled_reports": False,
        "white_label": False, "ai_calls": 20, "slack": False, "ingest_events": 10_000,
    },
    "agency": {
        "name": "Growth", "price": 30, "price_inr": 2499, "websites": 10, "min_interval_sec": 60, "history_days": 90,
        "ssl": True, "seo_audit": True, "seo_pages": 25, "content_checks": 50, "api_monitors": 10, "browser_tests": 10, "browser_minutes": 120,
        "js_monitoring": True, "team_members": 3, "reports": True, "scheduled_reports": True,
        "white_label": False, "ai_calls": 50, "slack": True, "ingest_events": 50_000,
    },
    "agency_pro": {
        "name": "Agency", "price": 60, "price_inr": 4999, "websites": 50, "min_interval_sec": 60, "history_days": 180,
        "ssl": True, "seo_audit": True, "seo_pages": 50, "content_checks": 200, "api_monitors": 40, "browser_tests": 40, "browser_minutes": 400,
        "js_monitoring": True, "team_members": 10, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 200, "slack": True, "ingest_events": 250_000,
    },
    "enterprise": {
        "name": "Enterprise", "price": None, "price_inr": None, "websites": 5000, "min_interval_sec": 30, "history_days": 730,
        "ssl": True, "seo_audit": True, "seo_pages": 100, "content_checks": 5000, "api_monitors": 2000, "browser_tests": 1000, "browser_minutes": 20000,
        "js_monitoring": True, "team_members": 500, "reports": True, "scheduled_reports": True,
        "white_label": True, "ai_calls": 5000, "slack": True, "ingest_events": 20_000_000,
    },
}

DEFAULT_PLAN = "free"


def trial_ends_at(ws: dict):
    return aware(ws.get("trial_ends_at"))


def paid_until(ws: dict):
    """Subscription access end. Infers from last payment for older workspaces."""
    until = aware(ws.get("paid_until"))
    if until:
        return until
    plan = ws.get("plan") or DEFAULT_PLAN
    if plan not in PAID_PLANS or ws.get("trial"):
        return None
    last = aware((ws.get("billing") or {}).get("last_paid_at")) or aware(ws.get("plan_changed_at"))
    if last:
        return last + timedelta(days=BILLING_PERIOD_DAYS)
    return None


def _access_base(**kwargs) -> dict:
    base = {
        "status": "open",
        "trial": False,
        "trial_active": False,
        "billing_active": False,
        "locked": False,
        "reason": None,
        "trial_ends_at": None,
        "paid_until": None,
        "seconds_left": 0,
        "trial_hours": TRIAL_HOURS,
        "billing_period_days": BILLING_PERIOD_DAYS,
        "effective_plan": DEFAULT_PLAN,
        "subscribed_plan": None,
    }
    base.update(kwargs)
    return base


def access(ws: dict) -> dict:
    """Trial / subscription lock state for API + UI.

    - trial_active: within 24h window — full Growth limits
    - billing_active: paid and paid_until in the future — plan limits
    - locked (trial_ended | subscription_ended): dashboard view-only until they pay
    - open: legacy / free without trial window
    """
    plan = ws.get("plan") or DEFAULT_PLAN
    trial_end = trial_ends_at(ws)
    until = paid_until(ws)

    # Enterprise stays open unless explicitly trial-locked
    if plan == "enterprise" and not ws.get("trial"):
        return _access_base(
            status="open",
            effective_plan="enterprise",
            subscribed_plan="enterprise",
            paid_until=until.isoformat() if until else None,
            billing_active=True,
        )

    # Active paid period
    if until and until > now() and plan in PAID_PLANS and not ws.get("trial"):
        left = int((until - now()).total_seconds())
        return _access_base(
            status="billing_active",
            billing_active=True,
            paid_until=until.isoformat(),
            seconds_left=left,
            effective_plan=plan,
            subscribed_plan=plan,
        )

    # Paid plan whose 30-day window expired (or never renewed)
    if plan in PAID_PLANS and not ws.get("trial") and until and until <= now():
        return _access_base(
            status="locked",
            locked=True,
            reason="subscription_ended",
            paid_until=until.isoformat(),
            effective_plan="free",
            subscribed_plan=plan,
        )

    # Still on a paid plan flag but no paid_until at all → legacy grandfather
    if plan in PAID_PLANS and not ws.get("trial") and until is None:
        return _access_base(
            status="open",
            billing_active=True,
            effective_plan=plan,
            subscribed_plan=plan,
        )

    # Trial window
    if trial_end:
        left = int((trial_end - now()).total_seconds())
        if left > 0:
            return _access_base(
                status="trial_active",
                trial=True,
                trial_active=True,
                trial_ends_at=trial_end.isoformat(),
                seconds_left=left,
                effective_plan=TRIAL_PLAN,
            )
        return _access_base(
            status="locked",
            trial=True,
            locked=True,
            reason="trial_ended",
            trial_ends_at=trial_end.isoformat(),
            effective_plan="free",
        )

    return _access_base(
        status="open",
        trial=bool(ws.get("trial")),
        effective_plan=plan,
    )


def is_locked(ws: dict) -> bool:
    return bool(access(ws)["locked"])


def require_unlocked(ws: dict):
    acc = access(ws)
    if not acc["locked"]:
        return
    if acc.get("reason") == "subscription_ended":
        raise ApiError(
            "Your monthly plan access has ended. Renew payment to unlock monitoring for another 30 days.",
            402,
            "subscription_locked",
        )
    raise ApiError(
        "Your 24-hour free trial has ended. Choose a plan to unlock monitoring.",
        402,
        "trial_locked",
    )


def extend_paid_until(ws: dict | None = None, *, from_dt=None):
    """Next paid_until after a successful payment (stacks remaining days if renewing early)."""
    base = from_dt or now()
    if ws:
        prev = paid_until(ws)
        if prev and prev > base:
            base = prev
    return base + timedelta(days=BILLING_PERIOD_DAYS)


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
