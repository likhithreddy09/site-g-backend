"""Asynchronous monitoring scheduler.

Claims due jobs atomically from Mongo (so multiple worker processes can run safely),
then executes them on bounded thread pools. HTTP and browser work use separate pools.
"""
import logging
import os
import socket
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from pymongo import ReturnDocument

from .config import Config
from .db import get_db
from .plans import limits
from .services import artifacts, browser, checks, incidents, reports
from .utils import now

log = logging.getLogger("siteguard.scheduler")

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"


class Pool:
    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
        self.executor = ThreadPoolExecutor(max_workers=size, thread_name_prefix=name)
        self.in_flight = 0
        self.lock = threading.Lock()
        self.completed = 0
        self.failed = 0

    @property
    def capacity(self) -> int:
        # Allow a small queue beyond workers; beyond that apply backpressure.
        return max(0, self.size * 2 - self.in_flight)

    def submit(self, job_type: str, fn, *args):
        with self.lock:
            self.in_flight += 1

        def run():
            started = now()
            ok, err = True, None
            try:
                fn(*args)
            except Exception as e:  # noqa: BLE001
                ok, err = False, f"{e}"
                log.error("job %s failed: %s\n%s", job_type, e, traceback.format_exc())
            finally:
                with self.lock:
                    self.in_flight -= 1
                    self.completed += 1
                    if not ok:
                        self.failed += 1
                if not ok:
                    get_db().job_log.insert_one({"at": now(), "job": job_type, "ok": False, "error": err[:500],
                                                 "started_at": started, "worker": WORKER_ID})

        self.executor.submit(run)


http_pool = Pool("http", Config.HTTP_WORKERS)
browser_pool = Pool("browser", Config.BROWSER_WORKERS)
_scheduler: BackgroundScheduler | None = None
_lags: list[float] = []


def _claim(collection: str, next_field: str, interval_of, extra: dict | None = None):
    db = get_db()
    t = now()
    q = {"paused": {"$ne": True}, next_field: {"$lte": t}, **(extra or {})}
    doc = db[collection].find_one(q, sort=[(next_field, 1)])
    if not doc:
        return None
    nxt = t + timedelta(seconds=interval_of(doc))
    claimed = db[collection].find_one_and_update({"_id": doc["_id"], next_field: doc[next_field]},
                                                 {"$set": {next_field: nxt, "claimed_by": WORKER_ID}},
                                                 return_document=ReturnDocument.AFTER)
    if claimed:
        _lags.append((t - doc[next_field]).total_seconds())
        del _lags[:-200]
    return claimed


def _interval(doc) -> int:
    return max(30, int(doc.get("interval_sec", 300)))


def dispatch() -> None:
    db = get_db()
    try:
        while http_pool.capacity > 0:
            site = _claim("websites", "next_check_at", _interval)
            if not site:
                break
            http_pool.submit("http_check", checks.run_website_check, site["_id"])
        while http_pool.capacity > 0:
            site = _claim("websites", "ssl_next_at", lambda d: 6 * 3600, {"ssl_enabled": True})
            if not site:
                break
            http_pool.submit("ssl_check", checks.run_ssl_check, site["_id"])
        while http_pool.capacity > 0:
            site = _claim("websites", "domain_next_at", lambda d: 24 * 3600, {"domain_enabled": True})
            if not site:
                break
            http_pool.submit("domain_check", checks.run_domain_check, site["_id"])
        while http_pool.capacity > 0:
            mon = _claim("api_monitors", "next_check_at", _interval)
            if not mon:
                break
            http_pool.submit("api_check", checks.run_api_check, mon["_id"])
        while browser_pool.capacity > 0:
            chk = _claim("page_checks", "next_check_at", lambda d: max(300, int(d.get("interval_sec", 3600))))
            if not chk:
                break
            browser_pool.submit("page_check", browser.run_page_check, chk["_id"])
        while browser_pool.capacity > 0:
            test = _claim("browser_tests", "next_check_at", lambda d: max(300, int(d.get("interval_sec", 3600))))
            if not test:
                break
            browser_pool.submit("browser_test", browser.run_browser_test, test["_id"], "schedule")
    except Exception as e:  # noqa: BLE001
        log.error("dispatch error: %s", e)
    heartbeat()


def heartbeat() -> None:
    t = now()
    db = get_db()
    overdue = db.websites.count_documents({"paused": {"$ne": True}, "next_check_at": {"$lt": t - timedelta(minutes=2)}})
    db.system.update_one({"_id": f"worker:{WORKER_ID}"}, {"$set": {
        "kind": "worker", "worker": WORKER_ID, "heartbeat_at": t,
        "pools": {p.name: {"size": p.size, "in_flight": p.in_flight, "completed": p.completed, "failed": p.failed}
                  for p in (http_pool, browser_pool)},
        "avg_dispatch_lag_sec": round(sum(_lags) / len(_lags), 2) if _lags else 0,
        "max_dispatch_lag_sec": round(max(_lags), 2) if _lags else 0,
        "overdue_checks": overdue,
    }}, upsert=True)


def retention() -> None:
    db = get_db()
    for ws in db.workspaces.find({}, {"plan": 1}):
        cutoff = now() - timedelta(days=limits(ws)["history_days"])
        db.check_results.delete_many({"workspace_id": ws["_id"], "at": {"$lt": cutoff}})
        db.test_runs.delete_many({"workspace_id": ws["_id"], "at": {"$lt": cutoff}})
        db.error_events.delete_many({"workspace_id": ws["_id"], "at": {"$lt": cutoff}})
        db.notifications.delete_many({"workspace_id": ws["_id"], "at": {"$lt": cutoff}})
        protected = {os.path.basename((c.get("baseline") or {}).get("path", "")) for c in db.page_checks.find({"workspace_id": ws["_id"]})}
        # Durable store (GridFS) + any leftover local cache files
        artifacts.delete_prefix(f"{ws['_id']}/", keep=protected, older_than_ts=cutoff.timestamp())
        art_dir = os.path.join(Config.STORAGE_DIR, "artifacts", str(ws["_id"]))
        if os.path.isdir(art_dir):
            for name in os.listdir(art_dir):
                p = os.path.join(art_dir, name)
                if name not in protected and os.path.isfile(p) and os.path.getmtime(p) < cutoff.timestamp():
                    try:
                        os.remove(p)
                    except OSError:
                        pass
    db.job_log.delete_many({"at": {"$lt": now() - timedelta(days=7)}})


def start() -> None:
    global _scheduler
    if _scheduler:
        return
    os.makedirs(os.path.join(Config.STORAGE_DIR, "artifacts"), exist_ok=True)
    _scheduler = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1})
    _scheduler.add_job(dispatch, "interval", seconds=Config.DISPATCH_INTERVAL_SEC, id="dispatch")
    _scheduler.add_job(incidents.run_escalations, "interval", seconds=60, id="escalations")
    _scheduler.add_job(reports.run_scheduled_reports, "interval", minutes=5, id="reports")
    _scheduler.add_job(retention, "interval", hours=6, id="retention", next_run_time=now() + timedelta(minutes=1))
    _scheduler.start()
    log.info("scheduler started as %s", WORKER_ID)
