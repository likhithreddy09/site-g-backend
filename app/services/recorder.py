"""Interactive journey recorder: a live browser session driven by clicks on screenshots.

Each session owns one Playwright browser on a dedicated thread (the sync API is thread-bound);
HTTP handlers talk to it through a command queue.
"""
import base64
import logging
import queue
import threading
import time
import uuid
from concurrent.futures import Future
from urllib.parse import urljoin, urlparse

from ..plans import add_usage
from ..security import redact, validate_target
from ..utils import ApiError
from .browser import _Guard, _launch, render_value

log = logging.getLogger(__name__)

VIEW = {"width": 1280, "height": 800}
IDLE_TIMEOUT = 600
MAX_LIFETIME = 1800
MAX_PER_WORKSPACE = 3

_sessions: dict[str, "RecorderSession"] = {}
_lock = threading.Lock()

ELEMENTS_JS = """() => {
  const out = [];
  const nodes = document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea, [role=button], [role=link], [role=checkbox], [role=tab], [role=menuitem], [onclick], label, summary');
  for (const el of nodes) {
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4 || r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) continue;
    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || st.display === 'none' || Number(st.opacity) === 0) continue;
    out.push({x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height)});
    if (out.length >= 250) break;
  }
  return out;
}"""

INSPECT_JS = """([x, y]) => {
  let el = document.elementFromPoint(x, y);
  if (!el) return null;
  const interactive = el.closest('a[href], button, input, select, textarea, [role=button], [role=link], [role=checkbox], [role=tab], [role=menuitem], label, summary');
  if (interactive && interactive.tagName === 'LABEL' && interactive.control) el = interactive.control;
  else if (interactive) el = interactive;
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const role = el.getAttribute('role') || '';
  const clean = (s) => (s || '').replace(/\\s+/g, ' ').trim();
  const text = clean(el.innerText || el.value || '').slice(0, 80);
  let kind = 'element';
  if (tag === 'select') kind = 'select';
  else if (tag === 'textarea' || (tag === 'input' && !['checkbox', 'radio', 'submit', 'button', 'reset', 'file', 'image'].includes(type))) kind = 'input';
  else if ((tag === 'input' && ['checkbox', 'radio'].includes(type)) || role === 'checkbox') kind = 'checkbox';
  else if (tag === 'a' || role === 'link') kind = 'link';
  else if (tag === 'button' || role === 'button' || (tag === 'input' && ['submit', 'button', 'reset', 'image'].includes(type)) || tag === 'summary' || el.onclick) kind = 'button';
  let labelText = '';
  if (el.labels && el.labels.length) labelText = clean(el.labels[0].innerText);
  if (!labelText && el.id) { const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]'); if (l) labelText = clean(l.innerText); }
  const aria = clean(el.getAttribute('aria-label'));
  const placeholder = clean(el.getAttribute('placeholder'));
  const name = el.getAttribute('name') || '';
  const human = (kind === 'input' || kind === 'select' || kind === 'checkbox') ? (labelText || aria || placeholder || name || type || tag) : (text || aria || el.getAttribute('title') || el.getAttribute('alt') || tag);
  const q = (s) => s.replace(/"/g, '\\\\"');
  const cands = [];
  for (const a of ['data-testid', 'data-test', 'data-qa', 'data-cy']) { const v = el.getAttribute(a); if (v) cands.push('[' + a + '="' + q(v) + '"]'); }
  if (el.id && !/\\d{3,}|^[0-9]|:/.test(el.id)) cands.push('#' + CSS.escape(el.id));
  if ((kind === 'button' || kind === 'link') && text && text.length <= 60) cands.push('role=' + (kind === 'link' ? 'link' : 'button') + '[name="' + q(text) + '"]');
  if (kind === 'input' || kind === 'select' || kind === 'checkbox') {
    if (name) cands.push(tag + '[name="' + q(name) + '"]' + (type === 'radio' ? '[value="' + q(el.value) + '"]' : ''));
    if (placeholder) cands.push(tag + '[placeholder="' + q(placeholder) + '"]');
  }
  if (aria) cands.push('[aria-label="' + q(aria) + '"]');
  if (kind === 'element' && text && text.length <= 60) cands.push('text="' + q(text) + '"');
  const path = [];
  let n = el;
  while (n && n.nodeType === 1 && n !== document.body && path.length < 6) {
    let s = n.tagName.toLowerCase();
    if (n.id && !/\\d{3,}|^[0-9]|:/.test(n.id)) { path.unshift('#' + CSS.escape(n.id)); break; }
    const sib = [...(n.parentElement ? n.parentElement.children : [])].filter(c => c.tagName === n.tagName);
    if (sib.length > 1) s += ':nth-of-type(' + (sib.indexOf(n) + 1) + ')';
    path.unshift(s);
    n = n.parentElement;
  }
  cands.push(path.join(' > '));
  const r = el.getBoundingClientRect();
  const form = el.closest('form');
  return {kind, tag, type, label: human.slice(0, 60), text, candidates: cands,
          options: tag === 'select' ? [...el.options].slice(0, 50).map(o => ({value: o.value, label: clean(o.text)})) : [],
          is_submit: type === 'submit' || (tag === 'button' && form && (!el.getAttribute('type') || el.getAttribute('type') === 'submit')),
          is_password: type === 'password', in_form: !!form,
          box: {x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height)}};
}"""


def _describe(action: str, label: str, kind: str, value: str = "", secret: bool = False) -> str:
    noun = {"input": "field", "select": "dropdown", "checkbox": "checkbox", "link": "link", "button": "button"}.get(kind, "")
    target = f"“{label}”" + (f" {noun}" if noun else "")
    if action == "click":
        return f"Click the {target}"
    if action == "fill":
        shown = "the secret value" if secret else ("a unique test email" if value == "{{email}}" else f"“{value}”")
        return f"Type {shown} into the {target}"
    if action == "select":
        return f"Choose “{value}” in the {target}"
    if action == "check":
        return f"Tick the {target}"
    if action == "assert_visible":
        return f"Check the {target} is shown"
    if action == "assert_text":
        return f"Check the page shows “{value}”"
    if action == "assert_url":
        return f"Check the web address contains “{value}”"
    if action == "press":
        return f"Press {value or 'Enter'}"
    if action == "wait":
        return f"Wait {round(int(value or 1000) / 1000, 1)} seconds"
    if action == "goto":
        return f"Go to {value}"
    return action


class RecorderSession:
    def __init__(self, ws: dict, user_id, start_url: str):
        self.id = uuid.uuid4().hex
        self.ws = ws
        self.ws_id = ws["_id"]
        self.user_id = user_id
        self.start_url = start_url
        self.created = time.time()
        self.last_used = time.time()
        self.cmds: queue.Queue = queue.Queue()
        self.closed = False
        self.thread = threading.Thread(target=self._run, daemon=True, name=f"recorder-{self.id[:6]}")
        self.thread.start()

    # ---- thread side
    def _run(self):
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as p:
                browser = _launch(p)
                ctx = browser.new_context(viewport=VIEW, user_agent="Mozilla/5.0 SiteGuardBot/1.0 (journey recorder)")
                self.page = ctx.new_page()
                self.page.set_default_timeout(10000)
                self.page.route("**/*", _Guard(urlparse(self.start_url).hostname, [], False))
                while not self.closed:
                    try:
                        fn, fut = self.cmds.get(timeout=5)
                    except queue.Empty:
                        if time.time() - self.last_used > IDLE_TIMEOUT or time.time() - self.created > MAX_LIFETIME:
                            break
                        continue
                    if fn is None:
                        fut.set_result(None)
                        break
                    try:
                        fut.set_result(fn(self.page))
                    except Exception as e:  # noqa: BLE001
                        fut.set_exception(e)
                browser.close()
        except Exception:  # noqa: BLE001
            log.exception("recorder session crashed")
        finally:
            self.closed = True
            add_usage(self.ws_id, "browser_seconds", round(time.time() - self.created, 1))
            with _lock:
                _sessions.pop(self.id, None)
            while not self.cmds.empty():
                _, fut = self.cmds.get_nowait()
                if fut and not fut.done():
                    fut.set_exception(RuntimeError("Recorder session ended"))

    # ---- request side
    def call(self, fn, timeout: float = 45):
        if self.closed:
            raise ApiError("This recording session has ended. Start a new recording.", 410, "session_closed")
        self.last_used = time.time()
        fut: Future = Future()
        self.cmds.put((fn, fut))
        try:
            return fut.result(timeout=timeout)
        except ApiError:
            raise
        except TimeoutError:
            raise ApiError("The page took too long to respond", 504)
        except Exception as e:  # noqa: BLE001
            raise ApiError(redact(str(e).split("\n")[0][:200]), 422)

    def close(self):
        if not self.closed:
            fut: Future = Future()
            self.cmds.put((None, fut))


def _settle(page):
    try:
        page.wait_for_load_state("load", timeout=8000)
        page.wait_for_load_state("networkidle", timeout=3000)
    except Exception:  # noqa: BLE001
        pass


def _state(page) -> dict:
    shot = page.screenshot(type="jpeg", quality=70)
    return {"url": page.url, "title": (page.title() or "")[:120], "screenshot": "data:image/jpeg;base64," + base64.b64encode(shot).decode(),
            "viewport": VIEW, "elements": page.evaluate(ELEMENTS_JS),
            "scroll_y": page.evaluate("() => Math.round(scrollY)"), "page_height": page.evaluate("() => document.documentElement.scrollHeight")}


def _goto(url: str):
    def fn(page):
        ok, reason = validate_target(url)
        if not ok:
            raise ApiError(f"This address cannot be opened: {reason}", 422)
        page.goto(url, wait_until="load", timeout=30000)
        _settle(page)
        return _state(page)
    return fn


def start(ws: dict, user_id, url: str) -> tuple["RecorderSession", dict]:
    ok, reason = validate_target(url)
    if not ok:
        raise ApiError(f"This address cannot be opened: {reason}", 422)
    with _lock:
        mine = [s for s in _sessions.values() if s.ws_id == ws["_id"] and not s.closed]
        if len(mine) >= MAX_PER_WORKSPACE:
            oldest = min(mine, key=lambda s: s.last_used)
            oldest.close()
        s = RecorderSession(ws, user_id, url)
        _sessions[s.id] = s
    return s, s.call(_goto(url), timeout=60)


def get(sid: str, ws_id) -> RecorderSession:
    s = _sessions.get(sid)
    if not s or s.ws_id != ws_id or s.closed:
        raise ApiError("This recording session has ended. Start a new recording.", 410, "session_closed")
    return s


def _resolve_selector(page, info: dict) -> str:
    for c in info.get("candidates") or []:
        try:
            if page.locator(c).count() == 1:
                return c
        except Exception:  # noqa: BLE001
            continue
    return (info.get("candidates") or [""])[-1]


def inspect(s: RecorderSession, x: int, y: int) -> dict:
    def fn(page):
        info = page.evaluate(INSPECT_JS, [x, y])
        if not info:
            raise ApiError("Nothing to select there", 422)
        info["selector"] = _resolve_selector(page, info)
        info.pop("candidates", None)
        return info
    return s.call(fn)


def perform(s: RecorderSession, data: dict) -> dict:
    action = data.get("action")
    sel = str(data.get("selector") or "")
    value = str(data.get("value") or "")
    label = str(data.get("label") or "")[:60]
    kind = str(data.get("kind") or "")
    secret = bool(data.get("secret"))
    execute = data.get("execute", True)
    if action not in ("click", "fill", "select", "check", "press", "assert_visible", "assert_text", "assert_url", "wait", "goto", "scroll"):
        raise ApiError("Unsupported action", 422)

    def fn(page):
        if action == "scroll":
            page.mouse.wheel(0, int(data.get("dy") or 600))
            page.wait_for_timeout(500)
            return {"state": _state(page), "step": None}
        if action == "goto":
            url = urljoin(page.url, value)
            _goto(url)(page)
            return {"state": _state(page), "step": {"action": "goto", "url": url, "description": _describe("goto", "", "", url)}}
        if execute:
            loc = page.locator(sel).first if sel else None
            if action == "click":
                loc.click(timeout=8000)
            elif action == "fill":
                loc.fill(render_value(value), timeout=8000)
            elif action == "select":
                loc.select_option(value, timeout=8000)
            elif action == "check":
                loc.check(timeout=8000)
            elif action == "press":
                page.keyboard.press(value or "Enter")
            elif action == "assert_visible":
                loc.wait_for(state="visible", timeout=5000)
            elif action == "assert_text":
                if value.lower() not in (page.inner_text("body") or "").lower():
                    raise ApiError(f"The page doesn't currently show “{value}”", 422)
            elif action == "assert_url":
                if value not in page.url:
                    raise ApiError(f"The current address doesn't contain “{value}”", 422)
            elif action == "wait":
                page.wait_for_timeout(min(int(value or 1000), 5000))
            if action in ("click", "press", "select", "check"):
                page.wait_for_timeout(600)
                _settle(page)
        step = {"action": action, "selector": sel if action not in ("assert_url", "wait", "press", "assert_text") else "",
                "value": value, "secret": secret, "description": _describe(action, label, kind, "••••" if secret else value, secret),
                "label": label, "kind": kind}
        if action == "assert_text" and sel and data.get("scoped"):
            step["selector"] = sel
        return {"state": _state(page), "step": step}
    return s.call(fn, timeout=60)


def refresh(s: RecorderSession) -> dict:
    return s.call(_state)
