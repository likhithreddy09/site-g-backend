"""Crawl a website in a real browser and discover its backend endpoints and login pages."""
import json
import logging
import re
import threading
import time
from urllib.parse import parse_qsl, urljoin, urlparse

from ..db import get_db
from ..plans import add_usage, quota_left
from ..security import validate_target
from ..utils import now
from .browser import VIEWPORT, _Guard, _launch
from .checks import registrable_domain

log = logging.getLogger(__name__)

MAX_PAGES = 12
MAX_ENDPOINTS = 200
PAGE_BUDGET_SEC = 120

TRACKER_HOSTS = re.compile(
    r"(google-analytics|googletagmanager|analytics\.google|doubleclick|googleadservices|googlesyndication|google\.com/(ccm|rmkt|pagead)|"
    r"clarity\.ms|facebook\.(com|net)|fbcdn|hotjar|segment\.(io|com)|mixpanel|amplitude|sentry\.io|intercom|crisp\.chat|tawk\.to|"
    r"hubspot|hs-analytics|linkedin\.com/(li|px)|ads\.linkedin|bing\.com|twitter\.com/i/adsct|t\.co/|tiktok|snapchat|newrelic|nr-data|"
    r"datadoghq|cloudflareinsights|stats\.wp\.com|pixel\.|/collect\b|/beacon\b|recaptcha|gstatic)", re.I)
STATIC_EXT = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|map|mp4|webm|mp3)$", re.I)
ID_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[A-Za-z0-9_-]{32,})$", re.I)
AUTH_PATH = re.compile(r"(log-?in|sign-?in|sign-?up|register|auth|oauth|token|session|otp|password|logout|sso)", re.I)
PRIORITY_LINK = re.compile(r"(log-?in|sign-?in|account|dashboard|portal|contact|checkout|cart|pricing|book|subscribe|search|app)", re.I)


def _template_path(path: str) -> str:
    parts = [("{id}" if ID_SEGMENT.match(p) else p) for p in path.split("/")]
    return "/".join(parts) or "/"


def _same_site(host: str, root: str) -> bool:
    return bool(host) and registrable_domain(host) == root


def _json_keys(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, dict):
        return [str(k)[:60] for k in list(data.keys())[:12]]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return ["[0]." + str(k)[:60] for k in list(data[0].keys())[:12]]
    return []


def _category(path: str, method: str, from_form: bool, content_type: str = "") -> str:
    if AUTH_PATH.search(path):
        return "auth"
    if from_form:
        return "form"
    if re.search(r"graphql|/gql\b", path, re.I) or "graphql" in (content_type or "").lower():
        return "graphql"
    if re.search(r"/(health|ready|livez|readyz|status|ping)\b", path, re.I):
        return "health"
    return "api" if method == "GET" else "write"


def _suggest(ep: dict) -> dict:
    """A conservative monitor configuration for a discovered endpoint."""
    statuses = [s for s in ep["statuses"] if 200 <= s < 400]
    assertions = []
    if ep.get("json_keys"):
        first = ep["json_keys"][0]
        if not first.startswith("[0]."):
            assertions.append({"type": "json_path", "path": first, "op": "exists", "value": ""})
    p95 = ep.get("max_ms") or 0
    assertions.append({"type": "response_time", "op": "lt", "value": str(max(1000, min(10000, int(p95 * 3) or 2000)))})
    return {"expected_statuses": statuses[:3] or [200], "assertions": assertions}


def _recommend(ep: dict) -> bool:
    """Endpoints worth monitoring by default: health, auth, frequent successful GETs, GraphQL, OpenAPI GETs."""
    if ep["category"] in ("health", "auth", "graphql"):
        return True
    if ep["method"] == "GET" and ep.get("count", 0) >= 2 and any(200 <= s < 400 for s in ep.get("statuses") or []):
        return True
    if ep.get("source") == "openapi" and ep["method"] == "GET":
        return True
    return False


def _progress(discovery_id, **fields):
    get_db().discoveries.update_one({"_id": discovery_id}, {"$set": fields})


class _Recorder:
    def __init__(self, root: str):
        self.root = root
        self.endpoints: dict[str, dict] = {}
        self.form_posts: set[str] = set()

    def on_response(self, page_url: str, response):
        try:
            req = response.request
            if req.resource_type not in ("xhr", "fetch", "document") or req.resource_type == "document" and req.method == "GET":
                return
            url = req.url
            if url.startswith(("data:", "blob:")) or TRACKER_HOSTS.search(url):
                return
            u = urlparse(url)
            if STATIC_EXT.search(u.path) or not _same_site(u.hostname or "", self.root):
                return
            path = _template_path(u.path)
            key = f"{req.method} {u.scheme}://{u.netloc}{path}"
            ep = self.endpoints.get(key)
            if not ep:
                if len(self.endpoints) >= MAX_ENDPOINTS:
                    return
                headers = req.headers
                ep = self.endpoints[key] = {
                    "key": key, "method": req.method, "url": f"{u.scheme}://{u.netloc}{path}", "host": u.netloc, "path": path,
                    "templated": path != u.path, "query_params": [], "statuses": [], "count": 0, "pages": [], "max_ms": 0,
                    "content_type": "", "json_keys": [],
                    "auth_required": bool(headers.get("authorization") or headers.get("x-api-key") or headers.get("x-auth-token")),
                    "sample_query": {},
                }
            ep["count"] += 1
            for k, v in parse_qsl(u.query, keep_blank_values=True):
                if k not in ep["query_params"] and len(ep["query_params"]) < 15:
                    ep["query_params"].append(k[:60])
                    # Values are kept only when they look like harmless paging/filter flags.
                    if len(v) <= 24 and re.fullmatch(r"[\w.,-]*", v) and not re.search(r"(token|key|secret|session|sig|auth|email|pass)", k, re.I):
                        ep["sample_query"][k[:60]] = v
            if response.status not in ep["statuses"]:
                ep["statuses"].append(response.status)
            if page_url not in ep["pages"] and len(ep["pages"]) < 5:
                ep["pages"].append(page_url)
            timing = req.timing or {}
            if timing.get("responseEnd", -1) > 0:
                ep["max_ms"] = max(ep["max_ms"], round(timing["responseEnd"] - max(0, timing.get("requestStart", 0))))
            ctype = (response.headers.get("content-type") or "").split(";")[0]
            ep["content_type"] = ctype
            if "json" in ctype and not ep["json_keys"] and req.method == "GET":
                try:
                    body = response.body()
                    if len(body) <= 1_000_000:
                        ep["json_keys"] = _json_keys(body.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            log.debug("discovery response capture failed", exc_info=True)


def _login_form(page) -> dict | None:
    js = """() => {
      const visible = (el) => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
      let pw = [...document.querySelectorAll('input[type=password]')].find(visible);
      let kind = 'password';
      if (!pw) {
        pw = [...document.querySelectorAll('input[type=tel], input[name*=otp i], input[name*=phone i], input[name*=mobile i], input[autocomplete=one-time-code], input[placeholder*=mobile i], input[placeholder*=phone i]')].find(visible);
        kind = 'otp';
      }
      if (!pw) return null;
      const form = pw.closest('form') || pw.closest('[role=dialog], .modal, [class*=modal i], [class*=dialog i]');
      const scope = form || document;
      const sel = (el) => {
        if (!el) return null;
        if (el.id) return '#' + CSS.escape(el.id);
        const txt = (el.innerText || '').trim();
        if (el.tagName === 'BUTTON' && txt && txt.length <= 30 && !el.name) return 'button:has-text("' + txt.replace(/"/g, '') + '")';
        if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name + '"]';
        if (el.type) return el.tagName.toLowerCase() + '[type="' + el.type + '"]';
        return el.tagName.toLowerCase();
      };
      const user = kind === 'otp' ? null : scope.querySelector('input[type=email], input[autocomplete=username], input[name*=user i], input[name*=email i], input[id*=user i], input[id*=email i], input[type=tel], input[type=text]');
      const label = (b) => (b.innerText || b.value || b.getAttribute('aria-label') || '').trim();
      const buttons = [...scope.querySelectorAll('button, input[type=submit], [role=button]')].filter(b => visible(b) && !/^(×|x|✕|close|cancel)$/i.test(label(b)));
      const submit = buttons.find(b => /(continue|send|otp|log ?in|sign ?in|submit|next|verify|proceed)/i.test(label(b)))
        || buttons.find(b => b.type === 'submit') || buttons[0];
      const isForm = form && form.tagName === 'FORM';
      return {kind, username_selector: kind === 'otp' ? sel(pw) : sel(user), password_selector: kind === 'otp' ? null : sel(pw), submit_selector: sel(submit),
              submit_text: submit ? (submit.innerText || submit.value || '').trim().slice(0, 40) : '',
              form_action: isForm && form.action ? form.action : null, form_method: isForm ? (form.method || 'get').toUpperCase() : null};
    }"""
    try:
        return page.evaluate(js)
    except Exception:  # noqa: BLE001
        return None


LOGIN_TRIGGER = re.compile(r"^\s*(log ?in|sign ?in|login / signup|login/signup|my account|client login|investor login)\s*$", re.I)


def _probe_login_buttons(ctx, url: str, rec: "_Recorder", logins: list, queue: list, seen: set) -> None:
    """Click sign-in buttons that are not plain links (JS modals / client-side routing). Nothing is submitted."""
    page = ctx.new_page()
    page.route("**/*", _Guard(urlparse(url).hostname, [], False))
    page.on("response", lambda r: rec.on_response(url, r))
    try:
        page.goto(url, wait_until="load", timeout=25000)
        page.wait_for_timeout(1000)
        candidates = page.locator("button, [role=button], a:not([href]), a[href='#'], a[href^='javascript']")
        idx = [i for i in range(min(candidates.count(), 80))
               if LOGIN_TRIGGER.match((candidates.nth(i).inner_text(timeout=1000) or "").strip()[:40])][:2]
        for i in idx:
            before = page.url
            try:
                candidates.nth(i).click(timeout=4000)
            except Exception:  # noqa: BLE001
                continue
            page.wait_for_timeout(2500)
            form = _login_form(page)
            target = page.url.split("#")[0]
            if form and not any(lg["page_url"] == target and lg.get("trigger") for lg in logins):
                logins.append({"page_url": target, "title": (page.title() or "")[:120],
                               "trigger": None if target != before else (candidates.nth(i).inner_text(timeout=1000) or "").strip()[:40], **form})
            if target != before and target not in seen:
                queue.insert(0, target)
            if target != before:
                page.goto(url, wait_until="load", timeout=25000)
                page.wait_for_timeout(800)
            else:
                page.keyboard.press("Escape")
    except Exception:  # noqa: BLE001
        log.debug("login probe failed", exc_info=True)
    finally:
        page.close()


def _group(u) -> str:
    segs = [s for s in u.path.split("/") if s]
    return f"{u.netloc}/{segs[0] if segs else ''}/{len(segs)}"


def run_discovery(discovery_id) -> None:
    from playwright.sync_api import sync_playwright

    db = get_db()
    disc = db.discoveries.find_one({"_id": discovery_id})
    site = db.websites.find_one({"_id": disc["website_id"]}) if disc else None
    if not site:
        return
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    start = site["url"]
    root = registrable_domain(urlparse(start).hostname or "")
    rec = _Recorder(root)
    pages, logins = [], []
    openapi_urls: list[str] = []
    t0 = time.time()
    try:
        ok, reason = validate_target(start)
        if not ok:
            raise ValueError(reason)
        _progress(discovery_id, phase="crawl", pages_done=0, endpoints_found=0, message="Opening your site…")
        with sync_playwright() as p:
            browser = _launch(p)
            ctx = browser.new_context(viewport=VIEWPORT, user_agent="Mozilla/5.0 WatchfrontBot/1.0 (endpoint discovery)")
            queue, seen, groups = [start], set(), {}
            _probe_login_buttons(ctx, start, rec, logins, queue, seen)
            while queue and len(pages) < MAX_PAGES and time.time() - t0 < PAGE_BUDGET_SEC:
                url = queue.pop(0).split("#")[0]
                if url in seen:
                    continue
                seen.add(url)
                g = _group(urlparse(url))
                if url != start and groups.get(g, 0) >= 2:
                    continue
                groups[g] = groups.get(g, 0) + 1
                if not validate_target(url)[0]:
                    continue
                page = ctx.new_page()
                guard = _Guard(urlparse(url).hostname, [], False)
                page.route("**/*", guard)
                page.on("response", lambda r, u=url: rec.on_response(u, r))
                info = {"url": url, "title": "", "status": None, "error": None}
                try:
                    resp = page.goto(url, wait_until="load", timeout=25000)
                    info["status"] = resp.status if resp else None
                    try:
                        page.wait_for_load_state("networkidle", timeout=6000)
                    except Exception:  # noqa: BLE001
                        pass
                    page.mouse.wheel(0, 4000)
                    page.wait_for_timeout(800)
                    info["title"] = (page.title() or "")[:120]
                    form = _login_form(page)
                    if form and not any(lg["page_url"] == url for lg in logins):
                        logins.append({"page_url": url, "title": info["title"], **form})
                        if form.get("form_action") and form.get("form_method") == "POST":
                            rec.form_posts.add(form["form_action"])
                    try:
                        from .openapi_discover import candidates_from_html
                        html = page.content()
                        openapi_urls.extend(candidates_from_html(html, url))
                    except Exception:  # noqa: BLE001
                        pass
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => [e.href, (e.innerText || '').trim().slice(0, 60)])")
                    fresh = []
                    for href, text in hrefs:
                        hu = urlparse(href)
                        if hu.scheme not in ("http", "https") or not _same_site(hu.hostname or "", root) or STATIC_EXT.search(hu.path):
                            continue
                        clean = f"{hu.scheme}://{hu.netloc}{hu.path}"
                        if clean in seen or clean in queue or clean in fresh:
                            continue
                        fresh.append((0 if PRIORITY_LINK.search(hu.path + " " + text) else 1, clean))
                    queue.extend(c for _, c in sorted(fresh)[:40])
                    queue.sort(key=lambda q: 0 if PRIORITY_LINK.search(urlparse(q).path) else 1)
                except Exception as e:  # noqa: BLE001
                    info["error"] = str(e).split("\n")[0][:200]
                pages.append(info)
                page.close()
                _progress(discovery_id, phase="crawl", pages_done=len(pages), endpoints_found=len(rec.endpoints),
                          message=f"Scanned {len(pages)} page{'s' if len(pages) != 1 else ''} · {len(rec.endpoints)} APIs so far")

            # Pull OpenAPI / Swagger specs linked from the site
            _progress(discovery_id, phase="openapi", pages_done=len(pages), endpoints_found=len(rec.endpoints),
                      message="Looking for OpenAPI / Swagger specs…")
            try:
                from .openapi_discover import candidates_from_html, fetch_specs
                # Always try well-known paths from the homepage origin
                openapi_urls = candidates_from_html("", start) + openapi_urls
                for spec_ep in fetch_specs(ctx, openapi_urls, root, limit=80):
                    key = spec_ep["key"]
                    if key in rec.endpoints:
                        rec.endpoints[key]["source"] = "openapi"
                        if spec_ep.get("name_hint") and not rec.endpoints[key].get("name_hint"):
                            rec.endpoints[key]["name_hint"] = spec_ep["name_hint"]
                    elif len(rec.endpoints) < MAX_ENDPOINTS:
                        rec.endpoints[key] = {**spec_ep, "sample_query": spec_ep.pop("sample_query", {})}
                _progress(discovery_id, phase="openapi", endpoints_found=len(rec.endpoints),
                          message=f"Merged OpenAPI specs · {len(rec.endpoints)} endpoints")
            except Exception:  # noqa: BLE001
                log.debug("openapi discovery failed", exc_info=True)
            browser.close()
        endpoints = []
        cat_order = {"health": 0, "auth": 1, "graphql": 2, "api": 3, "form": 4, "write": 5}
        for ep in rec.endpoints.values():
            ep.setdefault("source", "traffic")
            ep["category"] = _category(ep["path"], ep["method"], ep["url"] in rec.form_posts, ep.get("content_type") or "")
            ep["suggested"] = _suggest(ep)
            ep["recommend"] = _recommend(ep)
            if "sample_query" in ep:
                ep["query"] = ep.pop("sample_query")
            elif "query" not in ep:
                ep["query"] = {}
            endpoints.append(ep)
        endpoints.sort(key=lambda e: (0 if e.get("recommend") else 1, cat_order.get(e["category"], 9), -e.get("count", 0)))
        status, error = "done", None
        _progress(discovery_id, phase="done", message=f"Found {len(endpoints)} endpoints")
    except Exception as e:  # noqa: BLE001
        log.exception("discovery failed")
        endpoints, status, error = [], "failed", str(e)[:300]
    secs = round(time.time() - t0, 1)
    add_usage(ws["_id"], "browser_seconds", secs)
    db.discoveries.update_one({"_id": discovery_id}, {"$set": {
        "status": status, "error": error, "finished_at": now(), "duration_sec": secs,
        "pages": pages, "login_pages": logins, "endpoints": endpoints,
        "phase": status, "pages_done": len(pages), "endpoints_found": len(endpoints),
        "message": error or f"Found {len(endpoints)} endpoints across {len(pages)} pages",
    }})


def start_discovery(ws: dict, site: dict, user_id) -> dict:
    db = get_db()
    running = db.discoveries.find_one({"website_id": site["_id"], "status": "running"})
    if running and (now() - running["started_at"]).total_seconds() < 300:
        return running
    if quota_left(ws, "browser_seconds", "browser_minutes", 60) <= 0:
        from ..utils import ApiError
        raise ApiError("Browser-test minutes for this month are used up", 402, "plan_limit")
    doc = {"workspace_id": ws["_id"], "website_id": site["_id"], "status": "running", "started_at": now(), "started_by": user_id,
           "pages": [], "login_pages": [], "endpoints": [], "added": [],
           "phase": "starting", "pages_done": 0, "endpoints_found": 0, "message": "Starting scan…"}
    doc["_id"] = db.discoveries.insert_one(doc).inserted_id
    threading.Thread(target=run_discovery, args=(doc["_id"],), daemon=True, name="discovery").start()
    return doc
