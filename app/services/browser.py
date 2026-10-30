import os
import random
import re
import shutil
import string
import time
from urllib.parse import urljoin, urlparse

from PIL import Image, ImageChops, ImageDraw

from ..config import Config
from ..db import get_db
from ..plans import add_usage, quota_left
from ..security import check_host_allowed, redact, strip_query, validate_target
from ..utils import now
from . import artifacts, incidents, notify
from .checks import http_request

VIEWPORT = {"width": 1366, "height": 900}

# Requests matching these are aborted unless a test explicitly allows payments.
PAYMENT_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"api\.stripe\.com/v1/(payment_intents|charges|setup_intents)/.*/confirm",
        r"api\.stripe\.com/v1/charges",
        r"paypal\.com/(checkoutnow|v2/checkout/orders/.*/capture)",
        r"api\.razorpay\.com/v1/payments",
        r"checkout\.shopify\.com/.*/processing",
        r"api\.braintreegateway\.com/.*/transactions",
        r"squareup\.com/v2/payments",
    ]
]

# Third-party / tracker noise — not useful as journey evidence.
_NOISE_HOST = re.compile(
    r"(google-analytics\.com|googletagmanager\.com|googleadservices\.com|"
    r"doubleclick\.net|googlesyndication\.com|google\.com/(ccm|rmkt|pagead|recaptcha)|"
    r"facebook\.net|facebook\.com/(tr|en_US/fbevents)|connect\.facebook\.net|"
    r"hotjar\.com|clarity\.ms|segment\.io|segment\.com|mixpanel\.com|"
    r"sentry\.io|newrelic\.com|nr-data\.net|fullstory\.com|heap-api\.com|"
    r"cdn\.amplitude\.com|api\.amplitude\.com)",
    re.I,
)
_NOISE_CONSOLE = re.compile(
    r"(ReactGA\.initialize|moment construction falls back|Download the React DevTools|"
    r"\[HMR\]|\[webpack-dev-server\]|Deprecation warning: value provided is not in a recognized RFC2822)",
    re.I,
)
_WORKER_ERROR = re.compile(r"Browser worker error|Executable doesn.?t exist|playwright", re.I)


def _artifact_dir(ws_id) -> str:
    d = os.path.join(Config.STORAGE_DIR, "artifacts", str(ws_id))
    os.makedirs(d, exist_ok=True)
    return d


def _rel(path: str) -> str:
    return os.path.relpath(path, os.path.join(Config.STORAGE_DIR, "artifacts"))


def _new_artifact(ws_id, prefix: str) -> str:
    name = f"{prefix}-{int(time.time() * 1000)}-{random.randint(1000, 9999)}.png"
    return os.path.join(_artifact_dir(ws_id), name)


def _persist(path: str) -> str:
    """Upload a local screenshot to GridFS and return its relative artifact path."""
    rel = _rel(path)
    artifacts.put_file(rel, src_path=path)
    return rel


class _Guard:
    """Route handler blocking private-network, payment, and user-blocked requests."""

    def __init__(self, start_host: str, blocked_patterns: list[str], allow_payments: bool):
        self.start_host = start_host
        self.blocked = [p for p in blocked_patterns if p]
        self.allow_payments = allow_payments
        self.host_ok: dict[str, bool] = {}
        self.aborted: list[dict] = []

    def __call__(self, route, request):
        url = request.url
        if url.startswith(("data:", "blob:", "about:")):
            return route.continue_()
        host = urlparse(url).hostname or ""
        if host not in self.host_ok:
            self.host_ok[host] = check_host_allowed(host)[0]
        reason = None
        if not self.host_ok[host]:
            reason = "private network"
        elif not self.allow_payments and request.method != "GET" and any(p.search(url) for p in PAYMENT_PATTERNS):
            reason = "payment endpoint blocked by safety policy"
        elif any(b in url for b in self.blocked):
            reason = "blocked by test configuration"
        if reason:
            self.aborted.append({"url": strip_query(url), "method": request.method, "reason": reason})
            return route.abort("blockedbyclient")
        headers = None
        if host == self.start_host:
            headers = {**request.headers, "x-watchfront-test": "1"}
        return route.continue_(headers=headers) if headers else route.continue_()


def _browsers_ready(path: str) -> bool:
    try:
        return bool(path) and os.path.isdir(path) and any(name.startswith("chromium") for name in os.listdir(path))
    except OSError:
        return False


def _ensure_browsers() -> None:
    """Ignore a PLAYWRIGHT_BROWSERS_PATH that has no Chrome, so launch uses the installed cache."""
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if configured and not _browsers_ready(configured):
        os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)


def _launch(p):
    _ensure_browsers()
    return p.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--no-sandbox"])


def _is_noise_url(url: str) -> bool:
    return bool(_NOISE_HOST.search(url or ""))


def _is_noise_console(text: str) -> bool:
    return bool(_NOISE_CONSOLE.search(text or ""))


def _attach_collectors(page, console: list, network: list):
    def on_console(m):
        if m.type not in ("error", "warning"):
            return
        text = redact(m.text[:500])
        if _is_noise_console(text):
            return
        console.append({"type": m.type, "text": text})

    def on_pageerror(e):
        text = redact(str(e)[:800])
        if _is_noise_console(text):
            return
        console.append({"type": "exception", "text": text})

    def on_requestfailed(r):
        url = strip_query(r.url)
        if _is_noise_url(url):
            return
        network.append({
            "url": url,
            "method": r.method,
            "error": (r.failure or "failed") if isinstance(r.failure, str) else "failed",
        })

    def on_response(r):
        if r.status < 400:
            return
        url = strip_query(r.url)
        if _is_noise_url(url):
            return
        network.append({"url": url, "method": r.request.method, "status": r.status})

    page.on("console", on_console)
    page.on("pageerror", on_pageerror)
    page.on("requestfailed", on_requestfailed)
    page.on("response", on_response)


# ------------------------------------------------------------------ page checks (content + visual + links)


def _diff_images(base_path: str, cur_path: str, ignore_regions: list[dict], ws_id) -> tuple[float, str]:
    base = Image.open(base_path).convert("RGB")
    cur = Image.open(cur_path).convert("RGB")
    if cur.size != base.size:
        cur = cur.resize(base.size)
    for img in (base, cur):
        d = ImageDraw.Draw(img)
        for r in ignore_regions or []:
            d.rectangle([r.get("x", 0), r.get("y", 0), r.get("x", 0) + r.get("w", 0), r.get("y", 0) + r.get("h", 0)], fill=(0, 0, 0))
    diff = ImageChops.difference(base, cur).convert("L").point(lambda v: 255 if v > 24 else 0)
    hist = diff.histogram()
    changed = hist[255]
    pct = round(changed / (base.size[0] * base.size[1]) * 100, 3)
    overlay = Image.blend(cur, Image.new("RGB", cur.size, (255, 255, 255)), 0.55)
    overlay.paste(Image.new("RGB", cur.size, (155, 27, 103)), mask=diff)
    out = _new_artifact(ws_id, "diff")
    overlay.save(out, optimize=True)
    artifacts.put_file(_rel(out), src_path=out)
    return pct, out


def run_page_check(check_id) -> dict | None:
    from playwright.sync_api import sync_playwright

    db = get_db()
    chk = db.page_checks.find_one({"_id": check_id})
    if not chk:
        return None
    ws = db.workspaces.find_one({"_id": chk["workspace_id"]})
    t0 = time.time()
    t = now()
    result = {"missing_texts": [], "missing_selectors": [], "broken_links": [], "visual": None, "console": [], "error": None}
    shot_path = None
    ok, reason = validate_target(chk["url"])
    if not ok:
        result["error"] = reason
    else:
        console, network = [], []
        try:
            with sync_playwright() as p:
                browser = _launch(p)
                ctx = browser.new_context(viewport=chk.get("viewport") or VIEWPORT, user_agent="Mozilla/5.0 WatchfrontBot/1.0")
                page = ctx.new_page()
                page.route("**/*", _Guard(urlparse(chk["url"]).hostname, [], False))
                _attach_collectors(page, console, network)
                page.goto(chk["url"], wait_until="load", timeout=30000)
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:  # noqa: BLE001
                    pass
                body_text = " ".join((page.inner_text("body") or "").lower().split())
                result["missing_texts"] = [x for x in chk.get("expected_texts") or [] if x and " ".join(x.lower().split()) not in body_text]
                for sel in chk.get("required_selectors") or []:
                    try:
                        if page.locator(sel).count() == 0:
                            result["missing_selectors"].append(sel)
                    except Exception:  # noqa: BLE001
                        result["missing_selectors"].append(sel)
                if chk.get("visual_enabled", True):
                    css = ",".join(chk.get("ignore_selectors") or [])
                    style = "*{animation:none!important;transition:none!important;caret-color:transparent!important}"
                    if css:
                        style += f"{css}{{visibility:hidden!important}}"
                    page.add_style_tag(content=style)
                    page.wait_for_timeout(300)
                    shot_path = _new_artifact(chk["workspace_id"], "page")
                    page.screenshot(path=shot_path, full_page=False)
                    artifacts.put_file(_rel(shot_path), src_path=shot_path)
                links = []
                if chk.get("check_links"):
                    links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                browser.close()
            result["console"] = console[:30]
            seen, broken = set(), []
            for href in links:
                href = href.split("#")[0]
                if not href.startswith(("http://", "https://")) or href in seen:
                    continue
                seen.add(href)
                if len(seen) > 60:
                    break
                try:
                    out = http_request(href, method="HEAD", timeout=8, max_redirects=4)
                    if out.status in (405, 403, 501):
                        out = http_request(href, method="GET", timeout=8, max_redirects=4)
                    if out.status >= 400:
                        broken.append({"url": href, "status": out.status})
                except Exception as e:  # noqa: BLE001
                    broken.append({"url": href, "error": str(e)[:120]})
            result["broken_links"] = broken
            result["links_checked"] = len(seen)
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Page could not be loaded: {str(e)[:300]}"

    if shot_path:
        baseline = chk.get("baseline")
        if not baseline:
            bpath = _new_artifact(chk["workspace_id"], "baseline")
            shutil.copy(shot_path, bpath)
            artifacts.put_file(_rel(bpath), src_path=bpath)
            db.page_checks.update_one({"_id": chk["_id"]}, {"$set": {"baseline": {"path": _rel(bpath), "at": t}}})
            result["visual"] = {"screenshot": _rel(shot_path), "baseline": _rel(bpath), "diff_pct": 0, "changed": False, "new_baseline": True}
        else:
            try:
                base_abs = artifacts.ensure_local(baseline["path"])
            except FileNotFoundError:
                bpath = _new_artifact(chk["workspace_id"], "baseline")
                shutil.copy(shot_path, bpath)
                artifacts.put_file(_rel(bpath), src_path=bpath)
                db.page_checks.update_one({"_id": chk["_id"]}, {"$set": {"baseline": {"path": _rel(bpath), "at": t}}})
                result["visual"] = {"screenshot": _rel(shot_path), "baseline": _rel(bpath), "diff_pct": 0, "changed": False,
                                    "new_baseline": True}
            else:
                pct, diff_path = _diff_images(base_abs, shot_path, chk.get("ignore_regions") or [], chk["workspace_id"])
                changed = pct > float(chk.get("threshold_pct", 1.0))
                result["visual"] = {"screenshot": _rel(shot_path), "baseline": baseline["path"], "diff": _rel(diff_path),
                                    "diff_pct": pct, "changed": changed}

    functional_fail = bool(result["error"] or result["missing_texts"] or result["missing_selectors"])
    res_doc = {"workspace_id": chk["workspace_id"], "website_id": chk.get("website_id"), "page_check_id": chk["_id"],
               "kind": "content", "at": t, "ok": not functional_fail and not result["broken_links"],
               "classification": "failure" if functional_fail else "ok", "error": result["error"],
               "duration_ms": int((time.time() - t0) * 1000), "details": result}
    rid = db.check_results.insert_one(res_doc).inserted_id
    site = db.websites.find_one({"_id": chk.get("website_id")}) if chk.get("website_id") else None
    client_id = (site or {}).get("client_id")

    vis = result.get("visual") or {}
    if vis.get("changed"):
        db.visual_changes.insert_one({"workspace_id": chk["workspace_id"], "page_check_id": chk["_id"], "website_id": chk.get("website_id"),
                                      "url": chk["url"], "at": t, "diff_pct": vis["diff_pct"], "screenshot": vis["screenshot"],
                                      "baseline": vis["baseline"], "diff": vis["diff"], "status": "pending_review", "result_id": rid})
        notify.dispatch(
            ws, "visual_change", f"Visual change on {chk['name']}",
            f"{chk['url']} looks different from the version you approved ({vis['diff_pct']}% of the screen changed). "
            "Open Watchfront to compare them side by side and tell us whether the change was on purpose.",
            severity="info", link=f"{Config.APP_URL}/app/checks/{chk['_id']}",
            kind="visual_change",
        )

    key = f"content:{chk['_id']}"
    if functional_fail:
        parts = []
        if result["error"]:
            parts.append(result["error"])
        if result["missing_texts"]:
            parts.append("Text no longer on the page: " + ", ".join(f"“{x}”" for x in result["missing_texts"]))
        if result["missing_selectors"]:
            labels = chk.get("element_labels") or {}
            parts.append("Missing from the page: " + ", ".join(labels.get(x, x) for x in result["missing_selectors"]))
        incidents.open_or_update(ws, key=key, source_type="page_check", source_id=chk["_id"], website_id=chk.get("website_id"),
                                 client_id=client_id, severity="major", title=f"Content check failed: {chk['name']}",
                                 summary=" · ".join(parts), evidence={"type": "check_result", "ref_id": rid, "summary": " · ".join(parts),
                                                                       "artifact": vis.get("screenshot")})
    else:
        incidents.auto_resolve(ws, key, "Expected content and elements are present again.")
    lkey = f"links:{chk['_id']}"
    if result["broken_links"]:
        incidents.open_or_update(ws, key=lkey, source_type="page_check", source_id=chk["_id"], website_id=chk.get("website_id"),
                                 client_id=client_id, severity="minor", title=f"{len(result['broken_links'])} broken links on {chk['name']}",
                                 summary=", ".join(b["url"] for b in result["broken_links"][:5]),
                                 evidence={"type": "check_result", "ref_id": rid, "summary": f"{len(result['broken_links'])} broken links"})
    elif chk.get("check_links") and not result["error"]:
        incidents.auto_resolve(ws, lkey, "No broken links found on latest scan.")

    db.page_checks.update_one({"_id": chk["_id"]}, {"$set": {
        "last_check_at": t, "last_result_id": rid,
        "status": "failing" if functional_fail else ("changed" if vis.get("changed") else "passing"),
        "last_diff_pct": vis.get("diff_pct"), "last_screenshot": vis.get("screenshot"), "last_broken_links": len(result["broken_links"]),
    }})
    return res_doc


# ------------------------------------------------------------------ browser journey tests

STEP_ACTIONS = {"goto", "click", "fill", "select", "check", "press", "wait_for", "wait", "assert_visible",
                "assert_not_visible", "assert_text", "assert_url", "screenshot"}


def render_value(v: str | None) -> str:
    if not v:
        return v or ""
    ts = str(int(time.time()))
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return (v.replace("{{timestamp}}", ts).replace("{{random}}", rnd)
             .replace("{{email}}", f"watchfront-test+{ts}{rnd}@example.com"))


def friendly_error(step: dict, msg: str) -> str:
    """Translate a Playwright error into a sentence a non-developer can act on."""
    action = step.get("action")
    label = step.get("label")
    noun = {"input": "field", "select": "dropdown", "checkbox": "checkbox", "link": "link", "button": "button"}.get(step.get("kind") or "", "element")
    what = f"the “{label}” {noun}" if label else "the element"
    low = msg.lower()
    if action == "assert_text" or "expected text" in low:
        return f"The page did not show “{step.get('value')}”. The message may have changed, or the previous step didn't work (for example a form wasn't submitted)."
    if action == "assert_url":
        return f"The web address never contained “{step.get('value')}”. The page may not have moved on after the previous step."
    if action == "assert_not_visible":
        return f"{what[0].upper() + what[1:]} was still on the page when it should have disappeared."
    if "navigation blocked" in low:
        return "Watchfront blocked this address for safety (private or internal network)."
    if action == "goto" or "net::err" in low or "navigating to" in low:
        return "The page could not be opened — the site may be down, slow, or blocking automated visitors."
    if "strict mode violation" in low:
        return f"More than one match was found for {what}. Re-record this step so Watchfront can pick a more specific target."
    if "not visible" in low or "outside of the viewport" in low or "intercepts pointer events" in low:
        return f"{what[0].upper() + what[1:]} was found but covered or hidden (for example by a popup or cookie banner)."
    if "timeout" in low or "waiting for" in low:
        return f"Couldn't find {what} within the time limit. It may have been renamed, moved, or the page didn't finish loading."
    if "not a <select>" in low or "did not find some options" in low:
        return f"The option “{step.get('value')}” is no longer available in {what}."
    if "exceeded its maximum duration" in low:
        return "The journey took longer than its maximum duration and was stopped."
    return msg


def requires_safety_confirmation(test: dict) -> bool:
    actions = [s.get("action") for s in test.get("steps") or []]
    return "fill" in actions and any(a in ("click", "press") for a in actions)


def _execute_steps(test: dict, ws_id) -> dict:
    from playwright.sync_api import sync_playwright

    steps_out, console, network = [], [], []
    final_shot = failure_shot = None
    ok = True
    error = None
    start = time.time()
    deadline = start + int(test.get("timeout_sec", 60))
    safety = test.get("safety") or {}
    guard = _Guard(urlparse(test["start_url"]).hostname, safety.get("blocked_patterns") or [], bool(safety.get("allow_payments")))
    with sync_playwright() as p:
        browser = _launch(p)
        ctx = browser.new_context(viewport=VIEWPORT, user_agent="Mozilla/5.0 WatchfrontBot/1.0 (synthetic test)")
        page = ctx.new_page()
        page.route("**/*", guard)
        _attach_collectors(page, console, network)
        page.set_default_timeout(15000)
        steps = [{"action": "goto", "url": test["start_url"], "description": "Open start page"}] + list(test.get("steps") or [])
        for idx, step in enumerate(steps):
            action = step.get("action")
            s0 = time.time()
            rec = {"index": idx, "action": action, "description": step.get("description") or "", "selector": step.get("selector"),
                   "label": step.get("label") or "", "kind": step.get("kind") or "", "ok": True, "error": None}
            if time.time() > deadline:
                rec.update(ok=False, error="Test exceeded its maximum duration")
            else:
                try:
                    timeout = int(step.get("timeout_ms") or 15000)
                    sel, val = step.get("selector"), render_value(step.get("value"))
                    if action == "goto":
                        url = urljoin(page.url if page.url.startswith("http") else test["start_url"], step.get("url") or val)
                        okt, reason = validate_target(url)
                        if not okt:
                            raise RuntimeError(f"Navigation blocked: {reason}")
                        page.goto(url, wait_until="load", timeout=max(timeout, 30000))
                    elif action == "click":
                        page.locator(sel).first.click(timeout=timeout)
                    elif action == "fill":
                        page.locator(sel).first.fill(val, timeout=timeout)
                        rec["value"] = "••••" if step.get("secret") else val
                    elif action == "select":
                        page.locator(sel).first.select_option(val, timeout=timeout)
                    elif action == "check":
                        page.locator(sel).first.check(timeout=timeout)
                    elif action == "press":
                        (page.locator(sel).first.press(val or "Enter", timeout=timeout) if sel else page.keyboard.press(val or "Enter"))
                    elif action == "wait_for":
                        page.locator(sel).first.wait_for(state="visible", timeout=timeout)
                    elif action == "wait":
                        page.wait_for_timeout(min(int(val or 1000), 10000))
                    elif action == "assert_visible":
                        page.locator(sel).first.wait_for(state="visible", timeout=timeout)
                    elif action == "assert_not_visible":
                        page.locator(sel).first.wait_for(state="hidden", timeout=timeout)
                    elif action == "assert_text":
                        target = page.locator(sel).first if sel else page.locator("body")
                        deadline_t = time.time() + timeout / 1000
                        while True:
                            txt = target.inner_text(timeout=timeout)
                            if val.lower() in txt.lower():
                                break
                            if time.time() > deadline_t:
                                raise AssertionError(f"Expected text '{val}' not found")
                            page.wait_for_timeout(250)
                    elif action == "assert_url":
                        page.wait_for_url(re.compile(re.escape(val)), timeout=timeout)
                    elif action == "screenshot":
                        path = _new_artifact(ws_id, "step")
                        page.screenshot(path=path)
                        rec["screenshot"] = _persist(path)
                    else:
                        raise ValueError(f"Unknown action '{action}'")
                except Exception as e:  # noqa: BLE001
                    msg = str(e).split("\n")[0][:300]
                    rec.update(ok=False, error=redact(msg))
            rec["duration_ms"] = int((time.time() - s0) * 1000)
            rec["url"] = strip_query(page.url) if page.url.startswith("http") else None
            if not rec["ok"]:
                rec["friendly"] = friendly_error(step, rec["error"] or "")
            steps_out.append(rec)
            if not rec["ok"]:
                ok = False
                error = f"Step {idx + 1} failed — {rec['friendly']}"
                try:
                    failure_shot = _new_artifact(ws_id, "fail")
                    page.screenshot(path=failure_shot, full_page=False)
                    rec["screenshot"] = _persist(failure_shot)
                except Exception:  # noqa: BLE001
                    failure_shot = None
                break
        if ok:
            try:
                final_shot = _new_artifact(ws_id, "final")
                page.screenshot(path=final_shot)
                _persist(final_shot)
            except Exception:  # noqa: BLE001
                final_shot = None
        browser.close()
    # skipped steps
    total = len(test.get("steps") or []) + 1
    for i in range(len(steps_out), total):
        steps_out.append({"index": i, "action": (([{"action": "goto"}] + list(test.get("steps") or []))[i]).get("action"),
                          "ok": None, "skipped": True})
    return {"ok": ok, "error": error, "steps": steps_out, "console": console[:50], "network_failures": network[:50],
            "blocked_requests": guard.aborted[:50], "duration_ms": int((time.time() - start) * 1000),
            "screenshot": _rel(failure_shot) if failure_shot else (_rel(final_shot) if final_shot else None)}


def run_browser_test(test_id, trigger: str = "schedule") -> dict | None:
    db = get_db()
    test = db.browser_tests.find_one({"_id": test_id})
    if not test:
        return None
    ws = db.workspaces.find_one({"_id": test["workspace_id"]})
    t = now()
    base = {"workspace_id": test["workspace_id"], "test_id": test["_id"], "website_id": test.get("website_id"), "at": t, "trigger": trigger}
    if quota_left(ws, "browser_seconds", "browser_minutes", 60) <= 0:
        run = {**base, "ok": False, "classification": "skipped", "error": "Monthly browser-test minutes exhausted for this plan.",
               "steps": [], "attempts": 0, "duration_ms": 0}
        run["_id"] = db.test_runs.insert_one(run).inserted_id
        db.browser_tests.update_one({"_id": test["_id"]}, {"$set": {"last_run_at": t, "status": "quota_exceeded"}})
        return run
    ok, reason = validate_target(test["start_url"])
    if not ok:
        run = {**base, "ok": False, "classification": "failure", "error": reason, "steps": [], "attempts": 0, "duration_ms": 0}
        run["_id"] = db.test_runs.insert_one(run).inserted_id
        return run
    attempts = []
    retries = int(test.get("retries", 1))
    for attempt in range(retries + 1):
        try:
            r = _execute_steps(test, test["workspace_id"])
        except Exception as e:  # noqa: BLE001
            r = {"ok": False, "error": f"Browser worker error: {str(e)[:300]}", "steps": [], "console": [], "network_failures": [],
                 "blocked_requests": [], "duration_ms": 0, "screenshot": None}
        attempts.append(r)
        add_usage(ws["_id"], "browser_seconds", round(r["duration_ms"] / 1000, 2))
        if r["ok"]:
            break
    final = attempts[-1]
    classification = "ok" if final["ok"] and len(attempts) == 1 else ("transient" if final["ok"] else "failure")
    run = {**base, **final, "classification": classification, "attempts": len(attempts),
           "previous_attempt_errors": [a["error"] for a in attempts[:-1]]}
    run["_id"] = db.test_runs.insert_one(run).inserted_id
    key = f"test:{test['_id']}"
    site = db.websites.find_one({"_id": test.get("website_id")}) if test.get("website_id") else None
    worker_fault = bool(_WORKER_ERROR.search(final.get("error") or ""))
    if final["ok"]:
        db.browser_tests.update_one({"_id": test["_id"]}, {"$set": {"last_run_at": t, "status": "passing", "consecutive_failures": 0,
                                                                     "last_run_id": run["_id"], "last_duration_ms": final["duration_ms"]}})
        incidents.auto_resolve(ws, key, f"Journey '{test['name']}' passed again.")
    elif worker_fault:
        # Infrastructure failure (missing browser binary, etc.) — not a site issue.
        db.test_runs.update_one({"_id": run["_id"]}, {"$set": {"classification": "infra"}})
        db.browser_tests.update_one({"_id": test["_id"]}, {"$set": {"last_run_at": t, "status": "error",
                                                                     "last_run_id": run["_id"],
                                                                     "last_duration_ms": final["duration_ms"],
                                                                     "last_error": final["error"]}})
    else:
        fails = int(test.get("consecutive_failures", 0)) + 1
        confirmed = fails >= int(test.get("failure_threshold", 1))
        db.browser_tests.update_one({"_id": test["_id"]}, {"$set": {"last_run_at": t, "status": "failing" if confirmed else "flaky",
                                                                     "consecutive_failures": fails, "last_run_id": run["_id"],
                                                                     "last_duration_ms": final["duration_ms"], "last_error": final["error"]}})
        if confirmed:
            incidents.open_or_update(ws, key=key, source_type="browser_test", source_id=test["_id"], website_id=test.get("website_id"),
                                     client_id=(site or {}).get("client_id"), severity=test.get("severity", "major"),
                                     title=f"User journey failing: {test['name']}", summary=final["error"] or "",
                                     evidence={"type": "test_run", "ref_id": run["_id"], "summary": final["error"],
                                               "artifact": final.get("screenshot")})
    return run
