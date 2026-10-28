"""On-demand "re-check": visit a website in a real browser and record the JavaScript errors,
missing files and failing API calls a visitor would hit. Works without the SDK installed."""
import time
from urllib.parse import urlparse

from ..db import get_db
from ..plans import add_usage
from ..security import redact, strip_query, validate_target
from ..utils import now
from .browser import VIEWPORT, _Guard, _launch
from .checks import registrable_domain
from .discovery import PRIORITY_LINK, STATIC_EXT, TRACKER_HOSTS

MAX_PAGES = 5
BUDGET_SEC = 60
IGNORED_PATHS = ("/favicon.ico",)


def _pick_pages(page, start: str, root: str, limit: int) -> list[str]:
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => [e.href, (e.innerText || '').trim().slice(0, 60)])")
    out, seen = [], {start.rstrip("/")}
    ranked = []
    for href, text in hrefs:
        u = urlparse(href)
        if u.scheme not in ("http", "https") or registrable_domain(u.hostname or "") != root or STATIC_EXT.search(u.path):
            continue
        clean = f"{u.scheme}://{u.netloc}{u.path}".rstrip("/")
        if clean in seen:
            continue
        seen.add(clean)
        ranked.append((0 if PRIORITY_LINK.search(u.path + " " + text) else 1, len(u.path), clean))
    groups: set[str] = set()
    for _, _, c in sorted(ranked):
        segs = [x for x in urlparse(c).path.split("/") if x]
        key = segs[0] if segs else ""
        if key in groups:
            continue
        groups.add(key)
        out.append(c)
        if len(out) >= limit:
            break
    return out


def _visit(ctx, url: str) -> tuple[dict, list[dict]]:
    """Open one page and return (page summary, problems found on it)."""
    problems: list[dict] = []
    page = ctx.new_page()
    page.route("**/*", _Guard(urlparse(url).hostname, [], False))

    def on_console(m):
        if m.type == "error" and not m.text.startswith("Failed to load resource"):
            problems.append({"kind": "js", "message": redact(m.text[:1000]), "stack": "", "source": strip_query((m.location or {}).get("url", ""))})

    def on_pageerror(e):
        name = getattr(e, "name", "") or "Error"
        msg = getattr(e, "message", "") or str(e)
        problems.append({"kind": "js", "message": redact(f"Uncaught {name}: {msg}"[:1000]), "stack": redact((getattr(e, "stack", "") or "")[:4000]), "source": ""})

    def on_response(r):
        if r.status < 400 or TRACKER_HOSTS.search(r.url) or urlparse(r.url).path in IGNORED_PATHS:
            return
        rt = r.request.resource_type
        u = strip_query(r.url)
        if rt in ("xhr", "fetch"):
            m = r.request.method
            problems.append({"kind": "api", "message": f"{m} {u} → {r.status}", "api": {"url": u, "method": m, "status": r.status, "duration": 0, "error": ""}})
        elif rt in ("script", "stylesheet", "image", "font", "media"):
            problems.append({"kind": "js", "message": f"Failed to load resource: {u}", "source": "resource", "stack": ""})

    def on_failed(r):
        if TRACKER_HOSTS.search(r.url) or (r.failure or "").endswith("ERR_BLOCKED_BY_CLIENT"):
            return
        u = strip_query(r.url)
        if r.resource_type in ("xhr", "fetch"):
            problems.append({"kind": "api", "message": f"{r.method} {u} → network error",
                             "api": {"url": u, "method": r.method, "status": 0, "duration": 0, "error": str(r.failure or "")[:200]}})
        elif r.resource_type in ("script", "stylesheet"):
            problems.append({"kind": "js", "message": f"Failed to load resource: {u}", "source": "resource", "stack": ""})

    page.on("console", on_console)
    page.on("pageerror", on_pageerror)
    page.on("response", on_response)
    page.on("requestfailed", on_failed)
    info = {"url": url, "title": "", "status": None, "error": None}
    try:
        resp = page.goto(url, wait_until="load", timeout=25000)
        info["status"] = resp.status if resp else None
        try:
            page.wait_for_load_state("networkidle", timeout=6000)
        except Exception:  # noqa: BLE001
            pass
        page.mouse.wheel(0, 3000)
        page.wait_for_timeout(1200)
        info["title"] = (page.title() or "")[:120]
    except Exception as e:  # noqa: BLE001
        msg = str(e).split("\n")[0]
        info["error"] = "The page took too long to load" if "Timeout" in msg else msg[:200]
    seen, unique = set(), []
    for p in problems:
        if p["message"] not in seen:
            seen.add(p["message"])
            unique.append(p)
    return info, (page, unique)


def run(ws: dict, site: dict, user_email: str, urls: list[str] | None = None) -> dict:
    from playwright.sync_api import sync_playwright

    from ..routes.errors import record_error

    db = get_db()
    start = site["url"]
    root = registrable_domain(urlparse(start).hostname or "")
    t0 = time.time()
    pages, found = [], []
    targets = [u for u in (urls or []) if validate_target(u)[0] and registrable_domain(urlparse(u).hostname or "") == root][:MAX_PAGES]
    error = None
    try:
        ok, reason = validate_target(start)
        if not ok:
            raise ValueError(reason)
        with sync_playwright() as p:
            browser = _launch(p)
            ctx = browser.new_context(viewport=VIEWPORT, user_agent="Mozilla/5.0 (Macintosh) Chrome/124 SiteGuardBot/1.0 (re-check)")
            queue = targets or [start]
            i = 0
            while i < len(queue) and len(pages) < MAX_PAGES and time.time() - t0 < BUDGET_SEC:
                url = queue[i]
                i += 1
                info, (page, problems) = _visit(ctx, url)
                if not targets and i == 1 and not info["error"]:
                    queue.extend(_pick_pages(page, start, root, MAX_PAGES - 1))
                page.close()
                for pr in problems:
                    grp = record_error(ws, site, kind=pr["kind"], message=pr["message"], stack=pr.get("stack", ""), source=pr.get("source", ""),
                                       api=pr.get("api"), page=url, browser="Chrome", os_="SiteGuard re-check", device="Desktop", origin="recheck")
                    found.append({"group_id": grp["_id"], "fingerprint": grp["fingerprint"], "kind": pr["kind"], "message": pr["message"], "page": url,
                                  "new": grp.get("count", 1) <= 1})
                info["problems"] = len(problems)
                pages.append(info)
            browser.close()
    except Exception as e:  # noqa: BLE001
        error = str(e).split("\n")[0][:300]

    fixed, not_reproduced = [], []
    if not error:
        visited = {strip_query(p["url"]) for p in pages if not p["error"]}
        found_fps = {f["fingerprint"] for f in found}
        for grp in db.error_groups.find({"website_id": site["_id"], "status": "active"}):
            if grp["fingerprint"] in found_fps:
                continue
            grp_pages = {k.replace("\uff0e", ".") for k in (grp.get("pages") or {})}
            if not grp_pages & visited:
                continue
            item = {"group_id": grp["_id"], "kind": grp["kind"], "message": grp["message"]}
            origins = grp.get("origins") or {}
            if origins.get("visitors") or not origins.get("recheck"):
                not_reproduced.append(item)
            else:
                db.error_groups.update_one({"_id": grp["_id"]}, {"$set": {"status": "resolved", "status_by": "re-check", "resolved_at": now()}})
                fixed.append(item)

    secs = round(time.time() - t0, 1)
    add_usage(ws["_id"], "browser_seconds", secs)
    doc = {"workspace_id": ws["_id"], "website_id": site["_id"], "at": now(), "by": user_email, "duration_sec": secs,
           "status": "failed" if error else "done", "error": error, "pages": pages, "targeted": bool(targets),
           "found": found, "fixed": fixed, "not_reproduced": not_reproduced}
    doc["_id"] = db.error_scans.insert_one(doc).inserted_id
    return doc

