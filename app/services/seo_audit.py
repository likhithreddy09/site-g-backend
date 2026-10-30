"""Friendly on-page SEO audit — one HTML fetch (+ optional robots.txt), scored 0–100."""

from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..db import get_db
from ..utils import now
from . import incidents
from .checks import TargetBlocked, classify_exception, http_request

# Weights sum to 100 for a clean score.
CHECKS = [
    ("https", 12),
    ("title", 14),
    ("meta_description", 12),
    ("h1", 10),
    ("canonical", 8),
    ("meta_robots", 10),
    ("viewport", 8),
    ("html_lang", 4),
    ("og_tags", 8),
    ("twitter_card", 4),
    ("images_alt", 6),
    ("charset", 2),
    ("sitemap", 2),
]

WEIGHT = dict(CHECKS)
PASS, WARN, FAIL = "pass", "warn", "fail"


def _item(cid: str, status: str, message: str, value: str | None = None, tip: str | None = None) -> dict:
    return {
        "id": cid,
        "label": _LABELS[cid],
        "status": status,
        "message": message,
        "value": (value or "")[:280] or None,
        "tip": tip,
        "weight": WEIGHT[cid],
    }


_LABELS = {
    "https": "HTTPS",
    "title": "Page title",
    "meta_description": "Meta description",
    "h1": "Main heading (H1)",
    "canonical": "Canonical URL",
    "meta_robots": "Indexing (robots)",
    "viewport": "Mobile viewport",
    "html_lang": "Page language",
    "og_tags": "Social share tags (Open Graph)",
    "twitter_card": "Twitter / X card",
    "images_alt": "Image alt text",
    "charset": "Character encoding",
    "sitemap": "Sitemap hint",
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _score(items: list[dict]) -> int:
    total = sum(WEIGHT.values())
    earned = 0.0
    for it in items:
        w = it["weight"]
        if it["status"] == PASS:
            earned += w
        elif it["status"] == WARN:
            earned += w * 0.5
    return max(0, min(100, round(earned / total * 100)))


def _meta(soup: BeautifulSoup, name: str | None = None, prop: str | None = None) -> str:
    if name:
        tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.I)})
    else:
        tag = soup.find("meta", attrs={"property": re.compile(f"^{re.escape(prop or '')}$", re.I)})
    if not tag:
        return ""
    return (tag.get("content") or "").strip()


def audit_html(url: str, html: str, *, final_url: str | None = None, robots_text: str | None = None) -> dict:
    """Parse HTML and return a friendly scored audit. Pure function for tests."""
    final = final_url or url
    soup = BeautifulSoup(html or "", "html.parser")
    items: list[dict] = []

    # HTTPS
    if final.lower().startswith("https://"):
        items.append(_item("https", PASS, "The page loads over HTTPS.", final))
    else:
        items.append(_item(
            "https", FAIL, "The final URL is not HTTPS.", final,
            tip="Redirect HTTP to HTTPS so visitors and Google see a secure site.",
        ))

    # Title
    title = (soup.title.string or "").strip() if soup.title else ""
    title = re.sub(r"\s+", " ", title)
    if not title:
        items.append(_item("title", FAIL, "No page title found.", tip="Add a unique <title> that describes the page (about 30–60 characters)."))
    elif len(title) < 15:
        items.append(_item("title", WARN, "Title is quite short.", title, tip="Aim for roughly 30–60 characters so it reads clearly in Google."))
    elif len(title) > 65:
        items.append(_item("title", WARN, f"Title is long ({len(title)} characters) and may get cut off in search.", title, tip="Keep titles around 50–60 characters."))
    else:
        items.append(_item("title", PASS, "Title looks good.", title))

    # Meta description
    desc = _meta(soup, name="description")
    if not desc:
        items.append(_item("meta_description", FAIL, "No meta description.", tip="Add a clear 1–2 sentence summary (about 50–160 characters)."))
    elif len(desc) < 50:
        items.append(_item("meta_description", WARN, "Meta description is short.", desc, tip="A little more detail helps the snippet in search results."))
    elif len(desc) > 165:
        items.append(_item("meta_description", WARN, f"Meta description is long ({len(desc)} characters).", desc[:120] + "…", tip="Trim to about 150–160 characters."))
    else:
        items.append(_item("meta_description", PASS, "Meta description looks good.", desc))

    # H1
    h1s = [re.sub(r"\s+", " ", h.get_text(" ", strip=True)) for h in soup.find_all("h1")]
    h1s = [h for h in h1s if h]
    if not h1s:
        items.append(_item("h1", FAIL, "No H1 heading on the page.", tip="Add one clear main heading (H1) that matches the topic."))
    elif len(h1s) > 1:
        items.append(_item("h1", WARN, f"Found {len(h1s)} H1 headings — usually one is enough.", h1s[0], tip="Keep a single main H1; use H2/H3 for sections."))
    else:
        items.append(_item("h1", PASS, "One clear H1 heading.", h1s[0]))

    # Canonical
    can = soup.find("link", attrs={"rel": lambda v: v and "canonical" in str(v).lower()})
    href = (can.get("href") or "").strip() if can else ""
    if not href:
        items.append(_item("canonical", WARN, "No canonical link.", tip="Add <link rel=\"canonical\" href=\"…\"> to point at the preferred URL."))
    else:
        abs_can = urljoin(final, href)
        host_ok = urlparse(abs_can).netloc == urlparse(final).netloc
        if not host_ok:
            items.append(_item("canonical", WARN, "Canonical points to a different domain.", abs_can, tip="Double-check this is intentional (e.g. regional site)."))
        else:
            items.append(_item("canonical", PASS, "Canonical URL is set.", abs_can))

    # Robots meta
    robots = (_meta(soup, name="robots") or "").lower()
    if "noindex" in robots:
        items.append(_item("meta_robots", FAIL, "Page is set to noindex — search engines should skip it.", robots, tip="Remove noindex if this page should appear in Google."))
    elif "nofollow" in robots:
        items.append(_item("meta_robots", WARN, "Page uses nofollow.", robots, tip="Only keep nofollow if you intentionally don't want links followed."))
    else:
        items.append(_item("meta_robots", PASS, "Page can be indexed.", robots or "index, follow (default)"))

    # Viewport
    vp = _meta(soup, name="viewport")
    if not vp:
        items.append(_item("viewport", FAIL, "No mobile viewport meta tag.", tip="Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">."))
    elif "width" not in vp.lower():
        items.append(_item("viewport", WARN, "Viewport tag looks incomplete.", vp))
    else:
        items.append(_item("viewport", PASS, "Mobile viewport is set.", vp))

    # html lang
    html_tag = soup.find("html")
    lang = (html_tag.get("lang") or "").strip() if html_tag else ""
    if not lang:
        items.append(_item("html_lang", WARN, "No language set on <html>.", tip="Add lang=\"en\" or lang=\"en-IN\" (or your language) on the <html> tag."))
    else:
        items.append(_item("html_lang", PASS, "Page language is set.", lang))

    # Open Graph
    og_title = _meta(soup, prop="og:title")
    og_desc = _meta(soup, prop="og:description")
    og_image = _meta(soup, prop="og:image")
    og_ok = sum(bool(x) for x in (og_title, og_desc, og_image))
    if og_ok == 3:
        items.append(_item("og_tags", PASS, "Open Graph title, description and image are set.", og_title))
    elif og_ok == 0:
        items.append(_item("og_tags", WARN, "No Open Graph tags for social sharing.", tip="Add og:title, og:description and og:image for nicer link previews."))
    else:
        missing = [n for n, v in (("title", og_title), ("description", og_desc), ("image", og_image)) if not v]
        items.append(_item("og_tags", WARN, f"Open Graph is incomplete (missing {', '.join(missing)}).", og_title or None, tip="Add the missing og:* tags."))

    # Twitter
    tw = _meta(soup, name="twitter:card") or _meta(soup, prop="twitter:card")
    if tw:
        items.append(_item("twitter_card", PASS, "Twitter/X card type is set.", tw))
    else:
        items.append(_item("twitter_card", WARN, "No twitter:card meta tag.", tip="Add twitter:card (e.g. summary_large_image) for nicer previews on X."))

    # Image alts (sample first 25 content images)
    imgs = [im for im in soup.find_all("img") if im.get("src") and not str(im.get("src", "")).startswith("data:")][:25]
    if not imgs:
        items.append(_item("images_alt", PASS, "No content images to check on this page."))
    else:
        with_alt = sum(1 for im in imgs if (im.get("alt") or "").strip())
        ratio = with_alt / len(imgs)
        msg = f"{with_alt} of {len(imgs)} images have alt text."
        if ratio >= 0.85:
            items.append(_item("images_alt", PASS, msg))
        elif ratio >= 0.5:
            items.append(_item("images_alt", WARN, msg, tip="Describe important images with short alt text for accessibility and SEO."))
        else:
            items.append(_item("images_alt", FAIL, msg, tip="Add meaningful alt text to images that convey content."))

    # Charset
    charset_tag = soup.find("meta", attrs={"charset": True}) or soup.find("meta", attrs={"http-equiv": re.compile("content-type", re.I)})
    if charset_tag:
        items.append(_item("charset", PASS, "Character encoding is declared."))
    else:
        items.append(_item("charset", WARN, "No charset meta tag.", tip="Add <meta charset=\"utf-8\"> near the top of <head>."))

    # Sitemap hint
    sm_link = soup.find("link", attrs={"rel": lambda v: v and "sitemap" in str(v).lower()})
    robots_sm = bool(robots_text and re.search(r"(?im)^sitemap:\s*\S+", robots_text))
    if sm_link or robots_sm:
        items.append(_item("sitemap", PASS, "Sitemap is referenced (page or robots.txt)."))
    else:
        items.append(_item(
            "sitemap", WARN, "No sitemap mentioned in the page or robots.txt.",
            tip="Publish /sitemap.xml and list it in robots.txt with a Sitemap: line.",
        ))

    # Keep checklist order stable
    order = {cid: i for i, (cid, _) in enumerate(CHECKS)}
    items.sort(key=lambda x: order.get(x["id"], 99))

    score = _score(items)
    passed = sum(1 for x in items if x["status"] == PASS)
    warned = sum(1 for x in items if x["status"] == WARN)
    failed = sum(1 for x in items if x["status"] == FAIL)
    improvements = [
        {"id": x["id"], "label": x["label"], "message": x["message"], "tip": x.get("tip"), "status": x["status"]}
        for x in items if x["status"] in (WARN, FAIL)
    ]

    return {
        "url": final,
        "checked_at": now(),
        "score": score,
        "grade": _grade(score),
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "checks": items,
        "improvements": improvements,
        "summary": _summary(score, failed, warned),
    }


def _summary(score: int, failed: int, warned: int) -> str:
    if failed == 0 and warned == 0:
        return "Looking solid — nothing urgent to fix on this page."
    if failed == 0:
        return f"Score {score}. A few easy tweaks could make this page clearer in search."
    if score >= 70:
        return f"Score {score}. Fix the {failed} important issue{'s' if failed != 1 else ''} below when you can."
    return f"Score {score}. Start with the red items — they matter most for search and sharing."


def run_seo_audit(site_id) -> dict | None:
    """Fetch the website homepage, audit it, store snapshot + history."""
    db = get_db()
    site = db.websites.find_one({"_id": site_id})
    if not site or not site.get("seo_enabled", True):
        return None
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    t = now()
    url = site["url"]
    try:
        out = http_request(url, timeout=12, headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"})
        html = out.text
        final = out.final_url
        robots_text = None
        try:
            origin = f"{urlparse(final).scheme}://{urlparse(final).netloc}"
            rob = http_request(f"{origin}/robots.txt", timeout=6, headers={"Accept": "text/plain,*/*;q=0.8"})
            if rob.status < 400:
                robots_text = rob.text[:50_000]
        except Exception:  # noqa: BLE001
            robots_text = None
        if out.status >= 400:
            snapshot = {
                "url": final,
                "checked_at": t,
                "score": 0,
                "grade": "F",
                "passed": 0,
                "warned": 0,
                "failed": 1,
                "checks": [_item("https", FAIL if not final.startswith("https://") else WARN,
                                 f"Page returned HTTP {out.status}.", final,
                                 tip="Fix the page response first; SEO checks need a working HTML page.")],
                "improvements": [],
                "summary": f"Could not audit — the page returned HTTP {out.status}.",
                "http_status": out.status,
                "error": f"HTTP {out.status}",
            }
            # still try parse if body looks like HTML
            if "<html" in html.lower() or "<title" in html.lower():
                snapshot = audit_html(url, html, final_url=final, robots_text=robots_text)
                snapshot["http_status"] = out.status
                snapshot["checked_at"] = t
        else:
            snapshot = audit_html(url, html, final_url=final, robots_text=robots_text)
            snapshot["http_status"] = out.status
            snapshot["checked_at"] = t
            snapshot["response_ms"] = out.elapsed_ms
    except Exception as e:  # noqa: BLE001
        kind, msg = classify_exception(e)
        snapshot = {
            "url": url,
            "checked_at": t,
            "score": 0,
            "grade": "F",
            "passed": 0,
            "warned": 0,
            "failed": 1,
            "checks": [],
            "improvements": [],
            "summary": "Could not reach the page to run the SEO audit.",
            "error": msg,
            "error_kind": kind,
        }

    ok = snapshot.get("score", 0) >= 60 and not snapshot.get("error")
    critical_fail = any(
        c.get("status") == FAIL and c.get("id") in ("https", "title", "meta_robots")
        for c in snapshot.get("checks") or []
    )
    res = {
        "workspace_id": site["workspace_id"],
        "website_id": site["_id"],
        "kind": "seo",
        "at": t,
        "ok": ok and not critical_fail,
        "classification": "ok" if ok and not critical_fail else "failure",
        "error": snapshot.get("error"),
        "details": snapshot,
    }
    rid = db.check_results.insert_one(res).inserted_id
    db.websites.update_one(
        {"_id": site["_id"]},
        {"$set": {"seo": snapshot, "seo_next_at": t + timedelta(hours=24)}},
    )

    key = f"seo:{site['_id']}"
    if critical_fail or snapshot.get("score", 0) < 50:
        host = urlparse(site["url"]).hostname or site.get("name")
        incidents.open_or_update(
            ws,
            key=key,
            source_type="seo",
            source_id=site["_id"],
            website_id=site["_id"],
            client_id=site.get("client_id"),
            severity="minor",
            title=f"SEO needs attention on {host}",
            summary=snapshot.get("summary") or f"SEO score {snapshot.get('score', 0)}",
            evidence={"type": "check_result", "ref_id": rid, "summary": snapshot.get("summary")},
        )
    elif ok:
        incidents.auto_resolve(ws, key, "SEO audit looks healthy again.")

    return snapshot
