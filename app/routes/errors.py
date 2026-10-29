import gzip
import hashlib
import json
import logging
import random
import re
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from flask import Blueprint, Response, g, jsonify, request
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError, DuplicateKeyError

from ..config import Config
from ..db import get_db
from ..plans import add_usage, limits, quota_left
from ..security import client_scope, redact, require, strip_query
from ..services import incidents
from ..services import hll
from ..services import stacktrace as st
from ..utils import ApiError, clamp_int, now, oid, ser

bp = Blueprint("errors", __name__)
log = logging.getLogger("watchfront.errors")

# --------------------------------------------------------------- SDK script

SDK_JS = r"""/* Watchfront browser monitoring v2 */
(function(w,d){
  if (w.__watchfront) return; w.__watchfront = 1;
  var s = d.currentScript || d.querySelector('script[data-site-key]'); if (!s) return;
  function opt(n, v){ var x = s.getAttribute('data-' + n); return x == null ? v : x; }
  var KEY = opt('site-key'), ENDPOINT = opt('endpoint', '__API__') + '/ingest';
  var RELEASE = opt('release', ''), ENV = opt('environment', ''), SAMPLE = parseFloat(opt('sample', '1'));
  var API = opt('capture-api', 'true') !== 'false', CONSOLE = opt('console-errors', 'false') === 'true';
  if (!KEY || !w.JSON || Math.random() > SAMPLE) return;
  var T0 = Date.now(), loc = w.location, nav = w.navigator, fetch0 = w.fetch;
  function rnd(){ return Math.random().toString(36).slice(2, 10) + T0.toString(36); }
  var SID; try { SID = sessionStorage.getItem('sg_sid') || rnd(); sessionStorage.setItem('sg_sid', SID); } catch(e){ SID = rnd(); }
  function url(u){ try { var x = new URL(u, loc.href); return x.origin + x.pathname; } catch(e){ return String(u).split(/[?#]/)[0]; } }
  function short(u){ try { var x = new URL(u, loc.href); return (x.origin === loc.origin ? '' : x.host) + x.pathname; } catch(e){ return String(u).split(/[?#]/)[0]; } }
  function txt(v){ try { return typeof v === 'string' ? v : v instanceof Error ? v.name + ': ' + v.message : JSON.stringify(v); } catch(e){ return String(v); } }

  var crumbs = [];
  function crumb(c, m){ crumbs.push({c: c, m: String(m).slice(0, 160), t: Date.now() - T0}); if (crumbs.length > 30) crumbs.shift(); }

  var NOISE = /ResizeObserver loop|^Script error\.?$|Non-Error promise rejection captured|-extension:\/\/|webkit-masked-url/i;
  var queue = [], pending = {}, sends = {}, uniq = 0, timer = 0;
  function capture(ev){
    var m = ev.message = String(ev.message || 'Unknown error').slice(0, 1000);
    if (NOISE.test(m) || NOISE.test((ev.stack || '').split('\n').slice(0, 3).join(' '))) return;
    var sig = ev.type + '|' + m + '|' + (ev.api ? ev.api.status : '');
    if (pending[sig]) { pending[sig].n++; return; }
    if (!sends[sig]) { if (uniq >= 40) return; uniq++; sends[sig] = 0; }
    if (sends[sig] >= 5) return;
    sends[sig]++;
    ev.n = 1; ev.page = url(loc.href); ev.t = Date.now() - T0; ev.crumbs = crumbs.slice(-20);
    pending[sig] = ev; queue.push(ev);
    if (ev.type !== 'api') crumb('error', m);
    if (queue.length >= 10) flush(); else if (!timer) timer = setTimeout(flush, 2000);
  }
  function flush(unloading){
    clearTimeout(timer); timer = 0;
    if (!queue.length) return;
    var batch = queue.splice(0, queue.length); pending = {};
    var body = JSON.stringify({v: 2, site_key: KEY, release: RELEASE, env: ENV, session: SID, ua: nav.userAgent,
      viewport: w.innerWidth + 'x' + w.innerHeight, events: batch});
    if (!unloading && fetch0 && body.length < 60000) {
      try { fetch0.call(w, ENDPOINT, {method: 'POST', body: body, keepalive: true, mode: 'cors', headers: {'Content-Type': 'text/plain'}}).catch(function(){}); return; } catch(e){}
    }
    try { if (nav.sendBeacon) nav.sendBeacon(ENDPOINT, body); } catch(e){}
  }
  d.addEventListener('visibilitychange', function(){ if (d.visibilityState === 'hidden') flush(true); });
  w.addEventListener('pagehide', function(){ flush(true); });

  w.addEventListener('error', function(e){
    var el = e.target;
    if (el && el !== w && el.tagName) {
      var src = el.src || el.href; if (!src) return;
      capture({type: 'js', message: 'Failed to load resource: ' + url(src), source: el.tagName.toLowerCase()}); return;
    }
    var err = e.error;
    capture({type: 'js', message: e.message || (err && err.message) || 'Script error', source: url(e.filename || ''), line: e.lineno, col: e.colno,
             stack: err && err.stack ? String(err.stack).slice(0, 6000) : ''});
  }, true);
  w.addEventListener('unhandledrejection', function(e){
    var r = e.reason;
    capture({type: 'js', message: 'Unhandled rejection: ' + (r && r.message ? (r.name ? r.name + ': ' : '') + r.message : txt(r)).slice(0, 500),
             stack: r && r.stack ? String(r.stack).slice(0, 6000) : ''});
  });
  d.addEventListener('securitypolicyviolation', function(e){
    capture({type: 'js', message: 'Blocked by Content Security Policy: ' + (short(e.blockedURI) || e.blockedURI) + ' (' + e.violatedDirective + ')', source: 'csp'});
  });

  function describe(el){
    for (var i = 0; el && i < 4; i++, el = el.parentElement) {
      var tag = (el.tagName || '').toLowerCase();
      if (/^(a|button|summary|select|label)$/.test(tag) || (el.getAttribute && el.getAttribute('role') === 'button') || (tag === 'input' && /submit|button|checkbox|radio/.test(el.type))) {
        var label = el.getAttribute('aria-label') || el.getAttribute('title') || (tag === 'input' ? el.name || el.type : (el.innerText || '').replace(/\s+/g, ' ').trim());
        return tag + (el.id ? '#' + el.id : '') + (label ? ' "' + label.slice(0, 50) + '"' : '');
      }
    }
    return null;
  }
  d.addEventListener('click', function(e){ var x = describe(e.target); if (x) crumb('click', x); }, true);
  d.addEventListener('submit', function(e){ var f = e.target; crumb('click', 'submitted form' + (f && f.id ? '#' + f.id : '') + (f && f.action ? ' → ' + short(f.action) : '')); }, true);

  crumb('nav', 'Opened ' + short(loc.href));
  function onNav(){ crumb('nav', 'Went to ' + short(loc.href)); }
  ['pushState', 'replaceState'].forEach(function(k){
    var orig = history[k]; if (!orig) return;
    history[k] = function(){ var r = orig.apply(this, arguments); onNav(); return r; };
  });
  w.addEventListener('popstate', onNav);

  ['error', 'warn'].forEach(function(level){
    var c = w.console, orig = c && c[level]; if (!orig) return;
    c[level] = function(){
      var a = [].slice.call(arguments);
      crumb('console', level + ': ' + a.map(txt).join(' '));
      if (CONSOLE && level === 'error') { var err = a.filter(function(x){ return x instanceof Error; })[0];
        capture({type: 'js', message: 'console.error: ' + (err ? err.message : a.map(txt).join(' ')), stack: err && err.stack ? String(err.stack).slice(0, 6000) : '', source: 'console'}); }
      return orig.apply(c, arguments);
    };
  });

  function req(method, u, status, ms, err){
    if (String(u).indexOf(ENDPOINT) === 0) return;
    var label = method + ' ' + short(u);
    crumb('api', label + ' → ' + (status || 'failed') + ' (' + ms + ' ms)');
    if (API && (status >= 400 || !status)) capture({type: 'api', message: label + ' → ' + (status || 'network error'),
      api: {url: url(u), method: method, status: status, duration: ms, error: err ? String(err).slice(0, 200) : ''}});
  }
  if (fetch0) w.fetch = function(input, init){
    var u = typeof input === 'string' ? input : input && input.url || String(input);
    var m = String(init && init.method || input && input.method || 'GET').toUpperCase(), t = Date.now();
    return fetch0.apply(this, arguments).then(function(r){ req(m, u, r.status, Date.now() - t); return r; },
      function(e){ req(m, u, 0, Date.now() - t, e && e.message || e); throw e; });
  };
  var X = w.XMLHttpRequest && XMLHttpRequest.prototype;
  if (X) {
    var open = X.open, send = X.send;
    X.open = function(m, u){ this.__sg = {m: String(m || 'GET').toUpperCase(), u: String(u)}; return open.apply(this, arguments); };
    X.send = function(){
      var x = this, t = Date.now();
      if (x.__sg) x.addEventListener('loadend', function(){ req(x.__sg.m, x.__sg.u, x.status, Date.now() - t); });
      return send.apply(this, arguments);
    };
  }
})(window, document);"""

_SDK_CACHE: dict[str, tuple[bytes, bytes, str]] = {}


@bp.get("/sdk.js")
def sdk():
    if Config.PUBLIC_API_URL not in _SDK_CACHE:
        body = SDK_JS.replace("__API__", Config.PUBLIC_API_URL).encode()
        _SDK_CACHE[Config.PUBLIC_API_URL] = (body, gzip.compress(body, 9), '"' + hashlib.sha1(body).hexdigest()[:16] + '"')
    body, zipped, etag = _SDK_CACHE[Config.PUBLIC_API_URL]
    if request.headers.get("If-None-Match") == etag:
        resp = Response(status=304)
    elif "gzip" in request.headers.get("Accept-Encoding", ""):
        resp = Response(zipped, mimetype="application/javascript")
        resp.headers["Content-Encoding"] = "gzip"
    else:
        resp = Response(body, mimetype="application/javascript")
    resp.headers["ETag"] = etag
    resp.headers["Vary"] = "Accept-Encoding"
    resp.headers["Cache-Control"] = "public, max-age=3600, stale-while-revalidate=86400"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


# --------------------------------------------------------------- ingestion

_buckets: dict[str, list] = defaultdict(lambda: [0.0, 0.0])
_lock = threading.Lock()
_RATE_PER_MIN = 600
_BOTS = re.compile(r"bot\b|crawl|spider|slurp|HeadlessChrome|Lighthouse|PhantomJS|Prerender|WatchfrontBot|facebookexternalhit|Google-InspectionTool", re.I)
_DEFAULT_IGNORE = ("ResizeObserver loop", "Script error.")
_EVENT_SAMPLE_FIRST = 20
_EVENT_KEEP = 50
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="error-write")


def _allow(key: str, n: int) -> bool:
    """Token bucket per site key, refilled at _RATE_PER_MIN events per minute."""
    with _lock:
        b = _buckets[key]
        t = time.time()
        b[1] = min(_RATE_PER_MIN, b[1] + (t - b[0]) * _RATE_PER_MIN / 60) if b[0] else _RATE_PER_MIN
        b[0] = t
        if b[1] < n:
            return False
        b[1] -= n
        return True


def _ua(ua: str) -> tuple[str, str, str]:
    ua = ua or ""
    browser = ("Edge" if "Edg/" in ua else "Samsung Internet" if "SamsungBrowser" in ua else "Opera" if "OPR/" in ua
               else "Chrome" if "Chrome/" in ua or "CriOS" in ua else "Firefox" if "Firefox/" in ua or "FxiOS" in ua
               else "Safari" if "Safari/" in ua else "Other")
    os_ = ("Windows" if "Windows" in ua else "Android" if "Android" in ua else "iOS" if re.search("iPhone|iPad", ua)
           else "macOS" if "Mac OS" in ua else "Linux" if "Linux" in ua else "Other")
    device = "Tablet" if re.search("iPad|Tablet", ua) else "Mobile" if re.search("Mobi|Android|iPhone", ua) else "Desktop"
    return browser, os_, device


def _key(k: str) -> str:
    return (k or "unknown").replace(".", "\uff0e").replace("$", "\uff04")[:200]


def _unkey(d: dict | None) -> dict:
    return {k.replace("\uff0e", ".").replace("\uff04", "$"): v for k, v in (d or {}).items()}


def _ms(t):
    return t.replace(microsecond=t.microsecond // 1000 * 1000)


def prepare(site: dict, *, kind: str, message: str, stack: str = "", source: str = "", line=None, col=None, api: dict | None = None,
            page: str = "", browser: str = "Other", os_: str = "Other", device: str = "Desktop", release: str = "", env: str = "",
            viewport: str = "", session: str = "", crumbs: list | None = None, n: int = 1, origin: str = "visitors") -> dict:
    """Normalise one event: parse the stack, fingerprint it, and work out whose code threw. CPU only — no database calls."""
    frames = st.annotate(st.parse_stack(stack), site["url"])
    c = st.culprit(frames)
    return {"kind": kind, "message": message, "stack": stack, "source": (source or "")[:300], "line": line, "col": col, "api": api,
            "page": strip_query(page)[:500], "browser": browser, "os": os_, "device": device, "release": (release or "")[:80],
            "env": (env or "")[:40], "viewport": (viewport or "")[:20], "session": (session or "")[:40], "crumbs": crumbs or [],
            "n": max(1, min(int(n or 1), 100)), "origin": origin, "frames": frames,
            "culprit": {"fn": c["fn"], "file": c["file"], "line": c["line"], "col": c["col"], "in_app": c["in_app"]} if c else None,
            "third_party": None if kind == "api" else st.third_party_host(frames, source or "", site["url"]),
            "noise": kind == "js" and st.is_extension_noise(frames, source or ""),
            "fp": st.fingerprint(kind, message, frames, api)}


def write_events(ws: dict, site: dict, evs: list[dict]) -> dict:
    """Persist prepared events for one website with a fixed number of database round trips, however many events there are."""
    db = get_db()
    rum = site.get("rum") or {}
    t = _ms(now())
    hour = t.replace(minute=0, second=0, microsecond=0)
    agg: dict[str, dict] = {}
    for ev in evs:
        a = agg.setdefault(ev["fp"], {"first": ev, "last": ev, "n": 0, "visitors": 0, "inc": Counter(), "sessions": set(), "samples": []})
        n = ev["n"]
        a["n"] += n
        a["last"] = ev
        if ev["origin"] == "visitors":
            a["visitors"] += n
            if ev["session"]:
                a["sessions"].add(ev["session"])
        inc = a["inc"]
        inc[f"origins.{ev['origin']}"] += n
        inc[f"pages.{_key(ev['page'])}"] += n
        inc[f"browsers.{_key(ev['browser'])}"] += n
        inc[f"os.{_key(ev['os'])}"] += n
        inc[f"devices.{_key(ev['device'])}"] += n
        if ev["release"]:
            inc[f"releases.{_key(ev['release'])}"] += n
        if len(a["samples"]) < 3:
            a["samples"].append(ev)

    def group_ops():
        ops = []
        for fp, a in agg.items():
            f, last = a["first"], a["last"]
            flt = {"website_id": site["_id"], "fingerprint": fp}
            ops.append(UpdateOne(flt, {
                "$setOnInsert": {"workspace_id": site["workspace_id"], "client_id": site.get("client_id"), "kind": f["kind"], "message": f["message"],
                                 "stack": f["stack"], "frames": f["frames"], "culprit": f["culprit"], "third_party": f["third_party"],
                                 "source": f["source"], "line": f["line"], "col": f["col"], "api": f["api"], "first_seen": t,
                                 "first_release": f["release"], "status": "active", "window_start": t, "window_count": 0},
                "$set": {"last_seen": t, "last_release": last["release"], "last_page": last["page"], "last_message": last["message"][:300]},
                "$inc": {"count": a["n"], **a["inc"]}, **({"$max": hll.max_ops(a["sessions"])} if a["sessions"] else {})}, upsert=True))
            if a["visitors"]:
                fresh = {"$gt": [{"$subtract": [t, "$window_start"]}, 600_000]}
                resolved = {"$eq": ["$status", "resolved"]}
                ops.append(UpdateOne(flt, [{"$set": {
                    "window_start": {"$cond": [fresh, t, "$window_start"]},
                    "window_count": {"$cond": [fresh, a["visitors"], {"$add": ["$window_count", a["visitors"]]}]},
                    "regressed_at": {"$cond": [resolved, t, "$regressed_at"]},
                    "status": {"$cond": [resolved, "active", "$status"]}}}]))
            elif any(e["origin"] != "visitors" for e in [f, last]):
                ops.append(UpdateOne({**flt, "status": "resolved"}, {"$set": {"status": "active", "regressed_at": t}}))
        return ops

    try:
        db.error_groups.bulk_write(group_ops(), ordered=True)
    except (BulkWriteError, DuplicateKeyError):
        db.error_groups.bulk_write(group_ops(), ordered=True)
    groups = {gr["fingerprint"]: gr for gr in db.error_groups.find({"website_id": site["_id"], "fingerprint": {"$in": list(agg)}})}

    for gr in groups.values():
        gr["users"] = hll.estimate(gr.get("hll"))

    def write_hourly():
        db.error_hourly.bulk_write([UpdateOne({"_id": f"{groups[fp]['_id']}:{hour:%Y%m%d%H}"},
                                              {"$inc": {"count": a["n"]}, **({"$max": hll.max_ops(a["sessions"])} if a["sessions"] else {}), "$setOnInsert": {"group_id": groups[fp]["_id"], "website_id": site["_id"],
                                                                                           "workspace_id": site["workspace_id"], "hour": hour}}, upsert=True)
                                   for fp, a in agg.items()], ordered=False)

    def write_samples():
        events, trims = [], []
        for fp, a in agg.items():
            gr = groups[fp]
            after = gr.get("count", a["n"])
            before = after - a["n"]
            keep = a["samples"][:max(0, _EVENT_SAMPLE_FIRST - before)] or (a["samples"][-1:] if before // 25 != after // 25 else [])
            for ev in keep:
                events.append({"workspace_id": site["workspace_id"], "website_id": site["_id"], "group_id": gr["_id"], "at": t, "n": ev["n"],
                               "page": ev["page"], "browser": ev["browser"], "os": ev["os"], "device": ev["device"], "release": ev["release"],
                               "env": ev["env"], "origin": ev["origin"], "viewport": ev["viewport"], "stack": ev["stack"][:3000], "api": ev["api"],
                               "message": ev["message"][:500], "crumbs": ev["crumbs"][-20:], "session": ev["session"][:8]})
            if before // 200 != after // 200:
                trims.append(gr["_id"])
        if events:
            db.error_events.insert_many(events, ordered=False)
        for gid in trims:
            old = [e["_id"] for e in db.error_events.find({"group_id": gid}, {"_id": 1}).sort("at", -1).skip(_EVENT_KEEP).limit(500)]
            if old:
                db.error_events.delete_many({"_id": {"$in": old}})

    def write_usage():
        add_usage(ws["_id"], "ingest_events", sum(a["n"] for a in agg.values()))

    for f in [_pool.submit(fn) for fn in (write_hourly, write_samples, write_usage)]:
        f.result()

    threshold = int(rum.get("alert_threshold", 10))
    for fp, a in agg.items():
        gr = groups[fp]
        if not a["visitors"] or gr.get("status") == "ignored":
            continue
        label = "API failures" if gr["kind"] == "api" else "JavaScript errors"
        users = gr.get("users", 0)
        who = f"{users} visitor{'s' if users != 1 else ''}" if users else "real visitors"
        wc = int(gr.get("window_count", 0))
        if wc >= threshold > wc - a["visitors"]:
            incidents.open_or_update(ws, key=f"{gr['kind']}err:{gr['_id']}", source_type="rum_api" if gr["kind"] == "api" else "js_errors",
                                     source_id=gr["_id"], website_id=site["_id"], client_id=site.get("client_id"),
                                     severity="major" if gr["kind"] == "api" or wc >= threshold * 5 else "minor",
                                     title=f"{label} spike on {site['name']}: {gr['message'][:80]}",
                                     summary=f"{wc} occurrences in the last 10 minutes, affecting {who}. Latest page: {gr.get('last_page')}",
                                     evidence={"type": "error_group", "ref_id": gr["_id"], "summary": gr["message"][:200]})
        elif gr.get("first_seen") == t and gr["kind"] == "js" and not gr.get("third_party") and rum.get("alert_new", True):
            incidents.open_or_update(ws, key=f"jserr:{gr['_id']}", source_type="js_errors", source_id=gr["_id"], website_id=site["_id"],
                                     client_id=site.get("client_id"), severity="minor",
                                     title=f"New JavaScript error on {site['name']}: {gr['message'][:80]}",
                                     summary=f"First seen just now on {gr.get('last_page')}" + (f" in release {gr['first_release']}" if gr.get("first_release") else "") + ".",
                                     evidence={"type": "error_group", "ref_id": gr["_id"], "summary": gr["message"][:200]})
    return groups


def record_error(ws: dict, site: dict, *, kind: str, message: str, stack: str = "", source: str = "", line=None, col=None,
                 api: dict | None = None, page: str = "", browser: str = "Other", os_: str = "Other", device: str = "Desktop",
                 release: str = "", viewport: str = "", origin: str = "visitors", session: str = "") -> dict:
    """Record a single error synchronously and return its group. `origin` is "visitors" (SDK) or "recheck" (Watchfront browser)."""
    ev = prepare(site, kind=kind, message=message, stack=stack, source=source, line=line, col=col, api=api, page=page, browser=browser,
                 os_=os_, device=device, release=release, viewport=viewport, session=session, origin=origin)
    return write_events(ws, site, [ev])[ev["fp"]]


# ---- async ingest queue: requests return immediately, a background thread writes in bulk

_queue: list[tuple] = []
_q_lock = threading.Lock()
_flusher: threading.Thread | None = None
_FLUSH_SEC = 1.5
_site_cache: dict[str, tuple[float, dict | None, dict | None]] = {}


def flush_queue() -> int:
    with _q_lock:
        items = _queue[:]
        _queue.clear()
    by_site: dict = {}
    for ws, site, ev in items:
        by_site.setdefault(site["_id"], (ws, site, []))[2].append(ev)
    for ws, site, evs in by_site.values():
        try:
            write_events(ws, site, evs)
        except Exception:  # noqa: BLE001
            log.exception("failed to write %d browser events for %s", len(evs), site.get("name"))
    return len(items)


def _flush_loop():
    while True:
        time.sleep(_FLUSH_SEC)
        if _queue:
            flush_queue()


def _enqueue(items: list[tuple]) -> None:
    global _flusher
    with _q_lock:
        _queue.extend(items)
        if _flusher is None or not _flusher.is_alive():
            _flusher = threading.Thread(target=_flush_loop, name="error-ingest", daemon=True)
            _flusher.start()


def _lookup(key: str) -> tuple[dict | None, dict | None]:
    hit = _site_cache.get(key)
    if hit and time.time() - hit[0] < 30:
        return hit[1], hit[2]
    db = get_db()
    site = db.websites.find_one({"site_key": key}, {"name": 1, "url": 1, "workspace_id": 1, "client_id": 1, "rum": 1, "site_key": 1})
    ws = db.workspaces.find_one({"_id": site["workspace_id"]}) if site else None
    if len(_site_cache) > 5000:
        _site_cache.clear()
    _site_cache[key] = (time.time(), site, ws)
    return site, ws


def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp


@bp.route("/ingest", methods=["POST", "OPTIONS"])
def ingest():
    if request.method == "OPTIONS":
        return _cors(Response(status=204))
    try:
        data = json.loads(request.get_data(as_text=True)[:200_000] or "{}")
    except ValueError:
        return _cors(Response(status=400))
    if not isinstance(data, dict):
        return _cors(Response(status=400))
    key = str(data.get("site_key") or "")
    site, ws = _lookup(key) if key else (None, None)
    if not site or not ws:
        return _cors(Response(status=404))
    rum = site.get("rum") or {}
    ua = str(data.get("ua") or request.headers.get("User-Agent") or "")
    if not rum.get("enabled", True) or _BOTS.search(ua):
        return _cors(Response(status=202))
    raw = data.get("events") if isinstance(data.get("events"), list) else [data]
    raw = [e for e in raw[:50] if isinstance(e, dict)]
    if not raw:
        return _cors(Response(status=202))
    if not limits(ws)["js_monitoring"] or quota_left(ws, "ingest_events", "ingest_events") <= 0:
        return _cors(Response(status=402))
    if not _allow(key, len(raw)):
        return _cors(Response(status=429))
    if random.random() > float(rum.get("sample_rate", 1.0)):
        return _cors(Response(status=202))
    browser, os_, device = _ua(ua)
    ignore = [p.lower() for p in (rum.get("ignore_patterns") or []) if p] + [p.lower() for p in _DEFAULT_IGNORE]
    session = re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("session") or ""))[:40]
    items = []
    for e in raw:
        kind = "api" if e.get("type") == "api" else "js"
        if (kind == "api" and not rum.get("capture_api", True)) or (e.get("source") == "console" and not rum.get("console_errors")):
            continue
        message = redact(str(e.get("message") or "Unknown error"))[:1000]
        if any(p in message.lower() for p in ignore):
            continue
        api = None
        if kind == "api" and isinstance(e.get("api"), dict):
            a = e["api"]
            api = {"url": strip_query(str(a.get("url") or ""))[:500], "method": str(a.get("method") or "GET")[:10],
                   "status": clamp_int(a.get("status"), 0, 999, 0), "duration": clamp_int(a.get("duration"), 0, 600000, 0),
                   "error": redact(str(a.get("error") or ""))[:200]}
        crumbs = [{"c": str(c.get("c") or "")[:10], "m": redact(str(c.get("m") or ""))[:160], "t": clamp_int(c.get("t"), 0, 86_400_000, 0)}
                  for c in (e.get("crumbs") or [])[-20:] if isinstance(c, dict)]
        ev = prepare(site, kind=kind, message=message, stack=redact(str(e.get("stack") or ""))[:6000], source=str(e.get("source") or ""),
                     line=e.get("line"), col=e.get("col"), api=api, page=str(e.get("page") or e.get("page_url") or ""), browser=browser,
                     os_=os_, device=device, release=str(data.get("release") or e.get("release") or rum.get("release") or ""),
                     env=str(data.get("env") or ""), viewport=str(data.get("viewport") or e.get("viewport") or ""), session=session,
                     crumbs=crumbs, n=clamp_int(e.get("n"), 1, 100, 1))
        if not ev["noise"]:
            items.append((ws, site, ev))
    if items:
        _enqueue(items)
    return _cors(Response(status=202))


# --------------------------------------------------------------- dashboard API


def _scope_q() -> dict:
    q = {"workspace_id": g.ws_id, **client_scope()}
    if request.args.get("website_id"):
        q["website_id"] = oid(request.args["website_id"])
    return q


def _trends(group_ids: list, hours: int) -> dict:
    since = now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
    out: dict = {gid: [0] * hours for gid in group_ids}
    for h in get_db().error_hourly.find({"group_id": {"$in": group_ids}, "hour": {"$gte": since}}, {"group_id": 1, "hour": 1, "count": 1}):
        i = int((h["hour"] - since).total_seconds() // 3600)
        if 0 <= i < hours:
            out[h["group_id"]][i] += h["count"]
    return out


def _group_out(gr: dict) -> dict:
    o = ser({k: v for k, v in gr.items() if k != "hll"})
    o["users"] = hll.estimate(gr.get("hll"))
    for k in ("pages", "browsers", "os", "devices", "releases"):
        o[k] = _unkey(gr.get(k))
    o.pop("frames", None)
    o.pop("stack", None)
    return o


@bp.get("/api/errors")
@require()
def list_groups():
    q = _scope_q()
    if request.args.get("kind") in ("js", "api"):
        q["kind"] = request.args["kind"]
    q["status"] = request.args.get("status", "active")
    if q["status"] == "all":
        q.pop("status")
    hours = clamp_int(request.args.get("hours"), 1, 24 * 90, 24 * 7)
    q["last_seen"] = {"$gte": now() - timedelta(hours=hours)}
    sort_by = request.args.get("sort", "")
    sort = [("count", -1)] if sort_by in ("count", "users") else [("last_seen", -1)]
    db = get_db()
    sites = {s["_id"]: s["name"] for s in db.websites.find({"workspace_id": g.ws_id}, {"name": 1})}
    projection = {"frames": 0, "stack": 0, "events": 0}
    paged = request.args.get("page") is not None

    def rows_for(groups: list) -> list:
        trends = _trends([gr["_id"] for gr in groups], 24)
        out = []
        for gr in groups:
            o = _group_out(gr)
            o["website_name"] = sites.get(gr["website_id"])
            o["trend"] = trends.get(gr["_id"], [])
            out.append(o)
        return out

    if not paged:
        groups = list(db.error_groups.find(q, projection).sort(sort).limit(300))
        rows = rows_for(groups)
        if sort_by == "users":
            rows.sort(key=lambda r: (r["users"], r["count"]), reverse=True)
        return jsonify(rows)

    page = clamp_int(request.args.get("page"), 1, 10_000, 1)
    per_page = clamp_int(request.args.get("per_page"), 5, 50, 10)
    if sort_by == "users":
        # Visitor counts are estimates, so they cannot be sorted in the database.
        ranked = list(db.error_groups.find(q, projection).sort([("count", -1)]).limit(1000))
        ranked.sort(key=lambda gr: (hll.estimate(gr.get("hll")), gr.get("count") or 0), reverse=True)
        total = len(ranked)
        pages = max(1, (total + per_page - 1) // per_page) if total else 1
        page = min(page, pages)
        start = (page - 1) * per_page
        page_rows = rows_for(ranked[start:start + per_page])
    else:
        total = db.error_groups.count_documents(q)
        pages = max(1, (total + per_page - 1) // per_page) if total else 1
        page = min(page, pages)
        groups = list(db.error_groups.find(q, projection).sort(sort).skip((page - 1) * per_page).limit(per_page))
        page_rows = rows_for(groups)
    return jsonify({"items": page_rows, "total": total, "page": page, "per_page": per_page, "pages": pages})


@bp.get("/api/errors/summary")
@require()
def summary():
    db = get_db()
    q = _scope_q()
    day = now() - timedelta(hours=24)
    site_q = {"workspace_id": g.ws_id, **client_scope(), **({"_id": q["website_id"]} if "website_id" in q else {})}
    site_ids = [s["_id"] for s in db.websites.find(site_q, {"_id": 1})]
    hourly = list(db.error_hourly.aggregate([{"$match": {"website_id": {"$in": site_ids}, "hour": {"$gte": day.replace(minute=0, second=0, microsecond=0)}}},
                                             {"$group": {"_id": "$hour", "n": {"$sum": "$count"}}}]))
    regs = hll.merge(*(h.get("hll") for h in db.error_hourly.find(
        {"website_id": {"$in": site_ids}, "hour": {"$gte": day.replace(minute=0, second=0, microsecond=0)}}, {"hll": 1})))
    since = day.replace(minute=0, second=0, microsecond=0)
    series = [0] * 25
    for h in hourly:
        i = int((h["_id"] - since).total_seconds() // 3600)
        if 0 <= i < 25:
            series[i] += h["n"]
    return jsonify({"open": db.error_groups.count_documents({**q, "status": "active"}),
                    "new_24h": db.error_groups.count_documents({**q, "first_seen": {"$gte": day}}),
                    "events_24h": sum(series), "visitors_24h": hll.estimate(regs), "series": series[-24:]})


@bp.get("/api/errors/<gid>")
@require()
def get_group(gid):
    db = get_db()
    gr = db.error_groups.find_one({"_id": oid(gid), "workspace_id": g.ws_id, **client_scope()})
    if not gr:
        raise ApiError("Error group not found", 404)
    o = _group_out(gr)
    o["stack"] = gr.get("stack", "")
    o["frames"] = gr.get("frames") or []
    o["events"] = ser(list(db.error_events.find({"group_id": gr["_id"]}).sort("at", -1).limit(_EVENT_KEEP)))
    o["website"] = ser(db.websites.find_one({"_id": gr["website_id"]}, {"name": 1, "url": 1}))
    o["trend"] = _trends([gr["_id"]], 24 * 14)[gr["_id"]]
    return jsonify(o)


@bp.patch("/api/errors/<gid>")
@require("member")
def update_group(gid):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("active", "resolved", "ignored"):
        raise ApiError("Invalid status", 422)
    res = get_db().error_groups.update_one({"_id": oid(gid), "workspace_id": g.ws_id},
                                           {"$set": {"status": status, "status_by": g.user["email"], "status_at": now()}})
    if not res.matched_count:
        raise ApiError("Error group not found", 404)
    return get_group(gid)


# --------------------------------------------------------------- re-check (browser scan)


def _scan_out(d: dict | None) -> dict | None:
    if not d:
        return None
    o = ser(d)
    for f in o.get("found") or []:
        f.pop("fingerprint", None)
    return o


def _scan_site(sid):
    site = get_db().websites.find_one({"_id": oid(sid), "workspace_id": g.ws_id})
    if not site:
        raise ApiError("Website not found", 404)
    return site


@bp.post("/api/websites/<sid>/recheck")
@require("member")
def recheck_site(sid):
    from ..services import error_scan
    site = _scan_site(sid)
    if quota_left(g.ws, "browser_seconds", "browser_minutes", 60) <= 0:
        raise ApiError("Browser minutes for this month are used up", 402, "plan_limit")
    urls = [str(u)[:500] for u in ((request.get_json(silent=True) or {}).get("urls") or [])][:5]
    return jsonify(_scan_out(error_scan.run(g.ws, site, g.user["email"], urls or None)))


@bp.get("/api/websites/<sid>/recheck")
@require()
def latest_recheck(sid):
    site = _scan_site(sid)
    return jsonify(_scan_out(get_db().error_scans.find_one({"website_id": site["_id"]}, sort=[("at", -1)])))
