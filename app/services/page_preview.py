"""One-shot page preview used by the content-check setup wizard.

Opens the page once, returns a screenshot plus clickable regions with plain-language labels and
robust selectors, and suggests what a non-technical user will probably want to watch.
"""
import base64
import re
import time
from urllib.parse import urlparse

from ..plans import add_usage
from ..security import validate_target
from ..utils import ApiError
from .browser import VIEWPORT, _Guard, _launch

MAX_HEIGHT = 3200

COLLECT_JS = r"""
(maxH) => {
  const stableId = (id) => id && !/\d{3,}|^[0-9]|[:.]|__|--|^(ember|react|radix|headlessui|mui)/i.test(id) && id.length < 40;
  const q = (v) => '"' + String(v).replace(/"/g, '\\"') + '"';
  const clean = (t) => (t || '').replace(/\s+/g, ' ').trim();
  const visible = (el) => {
    const s = getComputedStyle(el);
    if (s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 4 && r.height > 4;
  };
  const unique = (sel) => { try { return document.querySelectorAll(sel).length === 1; } catch { return false; } };
  const cssPath = (el) => {
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && parts.length < 6) {
      if (cur.getAttribute('data-testid')) { parts.unshift(`[data-testid=${q(cur.getAttribute('data-testid'))}]`); break; }
      if (stableId(cur.id)) { parts.unshift('#' + CSS.escape(cur.id)); break; }
      const tag = cur.tagName.toLowerCase();
      if (tag === 'body') { parts.unshift('body'); break; }
      const sibs = cur.parentElement ? [...cur.parentElement.children].filter((c) => c.tagName === cur.tagName) : [];
      parts.unshift(sibs.length > 1 ? `${tag}:nth-of-type(${sibs.indexOf(cur) + 1})` : tag);
      cur = cur.parentElement;
      if (unique(parts.join(' > '))) break;
    }
    return parts.join(' > ');
  };
  const selectorFor = (el, kind) => {
    const tag = el.tagName.toLowerCase();
    if (el.getAttribute('data-testid')) return `[data-testid=${q(el.getAttribute('data-testid'))}]`;
    if (stableId(el.id)) return `${tag}#${CSS.escape(el.id)}`;
    if (kind === 'form') {
      if (el.getAttribute('name')) return `form[name=${q(el.getAttribute('name'))}]`;
      if (el.querySelector('textarea')) return 'form:has(textarea)';
      if (el.querySelector('input[type=email]')) return 'form:has(input[type=email])';
      if (el.querySelector('input[type=search]')) return 'form:has(input[type=search])';
    }
    if (['nav', 'header', 'footer', 'main'].includes(tag) && document.querySelectorAll(tag).length === 1) return tag;
    if (kind === 'logo') return el.closest('header') ? 'header img' : cssPath(el);
    if (tag === 'img' && el.getAttribute('alt')) return `img[alt=${q(el.getAttribute('alt'))}]`;
    if (tag === 'iframe' && el.src) { try { return `iframe[src*=${q(new URL(el.src).hostname)}]`; } catch {} }
    return cssPath(el);
  };
  const formLabel = (f) => {
    const t = clean(f.innerText).toLowerCase();
    const fields = f.querySelectorAll('input:not([type=hidden]):not([type=submit]), textarea, select').length;
    if (f.querySelector('input[type=password]')) return ['Login form', fields];
    if (f.querySelector('input[type=search]') || /search/.test(f.getAttribute('role') || '') || (fields === 1 && /search/.test(t))) return ['Search box', fields];
    if (f.querySelector('textarea') || /contact|enquir|inquir|message|get in touch/.test(t)) return ['Contact form', fields];
    if (fields <= 2 && f.querySelector('input[type=email]')) return ['Newsletter sign-up', fields];
    return ['Form', fields];
  };

  const H = Math.min(document.documentElement.scrollHeight, maxH);
  const out = [];
  const seen = new Set();
  const floating = (el) => {
    for (let cur = el; cur && cur !== document.body; cur = cur.parentElement) {
      const pos = getComputedStyle(cur).position;
      if (pos === 'fixed') return !cur.matches('nav, header, [role=navigation], [class*=navbar i], [class*=header i]');
    }
    return false;
  };
  const push = (el, kind, label, text) => {
    if (seen.has(el) || !visible(el)) return;
    const r = el.getBoundingClientRect();
    const y = r.top + scrollY;
    if (y > H) return;
    seen.add(el);
    out.push({ kind, label: clean(label).slice(0, 80), text: clean(text).slice(0, 120), selector: selectorFor(el, kind), floating: floating(el),
               box: { x: Math.round(r.left + scrollX), y: Math.round(y), w: Math.round(r.width), h: Math.round(Math.min(r.height, H - y)) } });
  };

  const logo = document.querySelector('header img, [class*=logo] img, img[alt*=logo i], a[class*=logo]');
  if (logo) push(logo, 'logo', 'Logo', '');
  const nav = document.querySelector('nav') || document.querySelector('header');
  if (nav) push(nav, 'menu', 'Main menu', '');
  document.querySelectorAll('form').forEach((f) => { const [l, n] = formLabel(f); push(f, 'form', `${l}${n ? ` (${n} field${n > 1 ? 's' : ''})` : ''}`, ''); });
  document.querySelectorAll('h1, h2, h3').forEach((h) => { const t = clean(h.innerText); if (t && t.length <= 90) push(h, 'heading', h.tagName === 'H1' ? 'Main heading' : 'Heading', t); });
  document.querySelectorAll('button, a[class*=btn], a[class*=button], a[class*=cta], [role=button], input[type=submit]').forEach((b) => {
    const t = clean(b.innerText || b.value || b.getAttribute('aria-label'));
    if (t && t.length <= 40 && !/^(×|x|close|menu|toggle|accept|reject|ok)$/i.test(t)) push(b, 'button', 'Button', t);
  });
  document.querySelectorAll('a[href^="tel:"]').forEach((a) => push(a, 'phone', 'Phone number', clean(a.innerText) || a.getAttribute('href').slice(4)));
  document.querySelectorAll('a[href^="mailto:"]').forEach((a) => push(a, 'email', 'Email address', clean(a.innerText) || a.getAttribute('href').slice(7)));
  document.querySelectorAll('img').forEach((i) => { const r = i.getBoundingClientRect(); if (r.width * r.height > 40000) push(i, 'image', i.alt ? `Image: ${i.alt}` : 'Large image', ''); });
  document.querySelectorAll('video, iframe').forEach((v) => push(v, v.tagName === 'VIDEO' ? 'video' : 'embed', v.tagName === 'VIDEO' ? 'Video' : 'Embedded content', ''));
  document.querySelectorAll('section, footer').forEach((s) => push(s, s.tagName === 'FOOTER' ? 'footer' : 'section', s.tagName === 'FOOTER' ? 'Footer' : 'Page section', ''));
  document.querySelectorAll('p').forEach((p) => { const t = clean(p.innerText); if (t.length >= 12 && t.length <= 160) push(p, 'text', 'Text', t); });

  const dyn = [];
  const addDyn = (sel, label) => { try { const el = [...document.querySelectorAll(sel)].find(visible); if (el) { const r = el.getBoundingClientRect(); dyn.push({ selector: sel, label, box: { x: Math.round(r.left + scrollX), y: Math.round(r.top + scrollY), w: Math.round(r.width), h: Math.round(r.height) } }); } } catch {} };
  addDyn('[id*=cookie i], [class*=cookie i], [class*=consent i], #onetrust-banner-sdk, #CybotCookiebotDialog', 'Cookie banner');
  addDyn('iframe[src*=tawk], iframe[src*=intercom], iframe[src*=crisp], iframe[src*=drift], iframe[src*=tidio], iframe[src*=zendesk], #hubspot-messages-iframe-container, [class*=chat-widget i], [id*=chat-widget i]', 'Chat bubble');
  addDyn('.swiper, .slick-slider, [class*=carousel i], [class*=slider i]', 'Image slider / carousel');
  addDyn('video[autoplay]', 'Autoplaying video');
  addDyn('[class*=marquee i], [class*=ticker i]', 'Scrolling ticker');
  addDyn('[class*=countdown i], [class*=timer i]', 'Countdown timer');
  addDyn('ins.adsbygoogle, [id*=google_ads], [class*=advert i]', 'Advert');
  const widgets = [...document.querySelectorAll('body *')].filter((el) => {
    if (getComputedStyle(el).position !== 'fixed' || !visible(el)) return false;
    const r = el.getBoundingClientRect();
    return r.top > innerHeight * 0.5 && r.width < 420 && r.height < 420 && !el.closest('nav, header');
  }).filter((el, _, all) => !all.some((o) => o !== el && o.contains(el)));
  widgets.slice(0, 4).forEach((el) => {
    const r = el.getBoundingClientRect();
    const t = clean(el.innerText || el.getAttribute('aria-label') || '').toLowerCase();
    const href = (el.querySelector('a') || {}).href || '';
    const label = /whatsapp/.test(href + t) ? 'WhatsApp button' : /chat/.test(t) ? 'Chat button' : /help|support|access/.test(t) ? 'Help / accessibility button' : 'Floating button';
    if (!dyn.some((d) => d.label === label)) dyn.push({ selector: cssPath(el), label, box: { x: Math.round(r.left + scrollX), y: Math.round(r.top + scrollY), w: Math.round(r.width), h: Math.round(r.height) } });
  });

  return { elements: out.slice(0, 300), dynamic: dyn, height: H, title: document.title };
}
"""

JUNK_BUTTON = re.compile(r"^(skip to|scroll|next|prev|previous|back|more|read more|learn more|open|close|show|hide|search)\b|cookie", re.I)


def _good_button(text: str) -> bool:
    return len(re.sub(r"[^A-Za-z]", "", text)) >= 3 and not JUNK_BUTTON.search(text)


def _suggest(elements: list[dict]) -> dict:
    texts, seen = [], set()

    def add(text, why, recommended=True):
        k = text.lower()
        if text and k not in seen and len(texts) < 12:
            seen.add(k)
            texts.append({"text": text, "why": why, "recommended": recommended})

    for e in elements:
        if e["kind"] == "heading" and e["label"] == "Main heading":
            add(e["text"], "Main heading")
    buttons = [e for e in elements if e["kind"] == "button" and e["box"]["y"] < 1400 and not e.get("floating") and _good_button(e["text"])]
    for i, e in enumerate(sorted(buttons, key=lambda e: len(e["text"].split()) > 4)):
        add(e["text"], "Button visitors click", i < 3 and len(e["text"].split()) <= 4)
    for e in elements:
        if e["kind"] in ("phone", "email") and not e.get("floating"):
            add(e["text"], e["label"])
    for e in elements:
        if e["kind"] == "heading" and e["label"] == "Heading":
            add(e["text"], "Section heading", False)

    parts, seen_sel = [], set()
    for e in elements:
        if e["kind"] in ("menu", "form", "logo", "footer") and e["selector"] not in seen_sel:
            seen_sel.add(e["selector"])
            parts.append({"label": e["label"], "selector": e["selector"], "recommended": e["kind"] in ("menu", "form"), "box": e["box"]})
    return {"texts": texts, "elements": parts[:10]}


def preview(ws: dict, url: str) -> dict:
    from playwright.sync_api import sync_playwright

    ok, reason = validate_target(url)
    if not ok:
        raise ApiError(f"This page can't be checked: {reason}", 422)
    t0 = time.time()
    try:
        with sync_playwright() as p:
            browser = _launch(p)
            ctx = browser.new_context(viewport=VIEWPORT, user_agent="Mozilla/5.0 WatchfrontBot/1.0")
            page = ctx.new_page()
            page.route("**/*", _Guard(urlparse(url).hostname, [], False))
            page.goto(url, wait_until="load", timeout=30000)
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:  # noqa: BLE001
                pass
            data = page.evaluate(COLLECT_JS, MAX_HEIGHT)
            shot = page.screenshot(type="jpeg", quality=65, full_page=True,
                                   clip={"x": 0, "y": 0, "width": VIEWPORT["width"], "height": data["height"]})
            final_url = page.url
            browser.close()
    except ApiError:
        raise
    except Exception as e:  # noqa: BLE001
        msg = str(e).split("\n")[0][:200]
        if "Timeout" in msg:
            msg = "The page took longer than 30 seconds to load."
        elif "ERR_NAME_NOT_RESOLVED" in msg:
            msg = "That web address doesn't exist — check the spelling."
        raise ApiError(f"We couldn't open that page. {msg}", 422) from e
    finally:
        add_usage(ws["_id"], "browser_seconds", int(time.time() - t0))

    return {
        "url": final_url, "title": data["title"], "width": VIEWPORT["width"], "height": data["height"],
        "fold": VIEWPORT["height"], "screenshot": "data:image/jpeg;base64," + base64.b64encode(shot).decode(),
        "elements": data["elements"], "dynamic": data["dynamic"], "suggestions": _suggest(data["elements"]),
    }
