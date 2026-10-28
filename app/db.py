from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database

from .config import Config

_client: MongoClient | None = None
_db: Database | None = None


def init_db() -> Database:
    global _client, _db
    if _db is not None:
        return _db
    _client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000, tz_aware=True)
    _client.admin.command("ping")
    _db = _client[Config.MONGO_DB]
    ensure_indexes(_db)
    return _db


def get_db() -> Database:
    return _db if _db is not None else init_db()


def ensure_indexes(db: Database) -> None:
    db.users.create_index("email", unique=True)
    db.members.create_index([("workspace_id", ASCENDING), ("user_id", ASCENDING)])
    db.members.create_index([("workspace_id", ASCENDING), ("email", ASCENDING)], unique=True)
    db.clients.create_index([("workspace_id", ASCENDING), ("name", ASCENDING)])
    db.websites.create_index([("workspace_id", ASCENDING), ("normalized_url", ASCENDING)], unique=True)
    db.websites.create_index([("paused", ASCENDING), ("next_check_at", ASCENDING)])
    db.websites.create_index("site_key", unique=True)
    db.check_results.create_index([("website_id", ASCENDING), ("kind", ASCENDING), ("at", DESCENDING)])
    db.check_results.create_index([("monitor_id", ASCENDING), ("at", DESCENDING)])
    db.check_results.create_index([("workspace_id", ASCENDING), ("at", DESCENDING)])
    db.api_monitors.create_index([("paused", ASCENDING), ("next_check_at", ASCENDING)])
    db.page_checks.create_index([("paused", ASCENDING), ("next_check_at", ASCENDING)])
    db.browser_tests.create_index([("paused", ASCENDING), ("next_check_at", ASCENDING)])
    db.test_runs.create_index([("test_id", ASCENDING), ("at", DESCENDING)])
    db.visual_changes.create_index([("page_check_id", ASCENDING), ("at", DESCENDING)])
    db.incidents.create_index([("workspace_id", ASCENDING), ("status", ASCENDING), ("last_detected_at", DESCENDING)])
    db.incidents.create_index([("workspace_id", ASCENDING), ("key", ASCENDING)])
    db.error_groups.create_index([("website_id", ASCENDING), ("fingerprint", ASCENDING)], unique=True)
    db.error_groups.create_index([("workspace_id", ASCENDING), ("last_seen", DESCENDING)])
    db.error_events.create_index([("group_id", ASCENDING), ("at", DESCENDING)])
    db.error_events.create_index("at", expireAfterSeconds=90 * 86400, name="error_events_ttl")
    db.error_groups.create_index([("website_id", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    db.error_hourly.create_index([("group_id", ASCENDING), ("hour", ASCENDING)])
    db.error_hourly.create_index([("website_id", ASCENDING), ("hour", ASCENDING)])
    db.error_hourly.create_index("hour", expireAfterSeconds=95 * 86400, name="error_hourly_ttl")
    db.notifications.create_index([("workspace_id", ASCENDING), ("at", DESCENDING)])
    db.reports.create_index("share_token", sparse=True)
    db.reports.create_index([("workspace_id", ASCENDING), ("created_at", DESCENDING)])
    db.report_schedules.create_index([("active", ASCENDING), ("next_run_at", ASCENDING)])
    db.audit_events.create_index([("workspace_id", ASCENDING), ("at", DESCENDING)])
    db.job_log.create_index([("at", DESCENDING)])
    db.discoveries.create_index([("website_id", ASCENDING), ("started_at", DESCENDING)])
