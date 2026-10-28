"""Micro-benchmark for browser-error ingestion. Uses a throwaway website + workspace and cleans up afterwards."""
import random
import sys
import time

from bson import ObjectId

from app import create_app
from app.db import get_db
from app.routes import errors as E

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300

STACK_CHROME = """TypeError: Cannot read properties of undefined (reading 'price')
    at renderCart (https://bench.example.com/static/js/main.4f9a2c1b.js:1:20450)
    at onClick (https://bench.example.com/static/js/main.4f9a2c1b.js:1:9921)"""
STACK_SAFARI = """renderCart@https://bench.example.com/static/js/main.4f9a2c1b.js:1:20460
onClick@https://bench.example.com/static/js/main.4f9a2c1b.js:1:9930"""

VARIANTS = [
    ("js", "Cannot read properties of undefined (reading 'price')", STACK_CHROME, "Chrome"),
    ("js", "undefined is not an object (evaluating 'item.price')", STACK_SAFARI, "Safari"),
    ("js", "Uncaught ReferenceError: gtag is not defined", "", "Chrome"),
    ("js", "Can't find variable: gtag", "", "Safari"),
] + [("js", f"Error number {i} in widget", "", "Chrome") for i in range(6)]

app = create_app(start_worker=False)
with app.app_context():
    db = get_db()
    ws = {"_id": ObjectId(), "plan": "agency_pro", "name": "bench"}
    db.workspaces.insert_one(ws)
    site = {"_id": ObjectId(), "workspace_id": ws["_id"], "name": "Bench", "url": "https://bench.example.com", "site_key": f"bench_{ObjectId()}",
            "rum": {"alert_threshold": 10 ** 9, "alert_new": False}}
    db.websites.insert_one(site)
    try:
        mode = sys.argv[2] if len(sys.argv) > 2 else "single"
        t0 = time.perf_counter()
        if mode == "batched":
            evs = []
            for i in range(N):
                kind, msg, stack, browser = random.choice(VARIANTS)
                evs.append(E.prepare(site, kind=kind, message=msg, stack=stack, page=f"https://bench.example.com/p{i % 7}", browser=browser,
                                     release="v1.2.3", session=f"s{random.randint(1, 80)}"))
            for i in range(0, N, 100):
                E.write_events(ws, site, evs[i:i + 100])
        else:
            for i in range(N):
                kind, msg, stack, browser = random.choice(VARIANTS)
                kw = {"session": f"s{random.randint(1, 80)}"} if "session" in E.record_error.__code__.co_varnames else {}
                E.record_error(ws, site, kind=kind, message=msg, stack=stack, page=f"https://bench.example.com/p{i % 7}",
                               browser=browser, release="v1.2.3", **kw)
        dt = time.perf_counter() - t0
        groups = db.error_groups.count_documents({"website_id": site["_id"]})
        events = db.error_events.count_documents({"website_id": site["_id"]})
        from app.services import hll; users = sum(hll.estimate(x.get("hll")) for x in db.error_groups.find({"website_id": site["_id"]}))
        print(f"[{mode}] {N} events in {dt:.2f}s -> {dt / N * 1000:.1f} ms/event, {N / dt:.0f} events/s | groups={groups} stored_events={events} users={users}")
    finally:
        for c in ("error_groups", "error_events", "error_sessions", "error_hourly", "incidents"):
            db[c].delete_many({"website_id": site["_id"]})
        db.websites.delete_one({"_id": site["_id"]})
        db.workspaces.delete_one({"_id": ws["_id"]})
        db.usage.delete_many({"workspace_id": ws["_id"]})
