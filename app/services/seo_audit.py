"""On-page SEO audit across the site — sitemap + internal links, scored 0–100."""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from datetime import timedelta
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from ..db import get_db
from ..plans import limits
from ..utils import now
from . import incidents
from .checks import classify_exception, http_request, registrable_domain
from .discovery import PRIORITY_LINK, STATIC_EXT

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

# Soft budget so a large crawl doesn't hang the API request forever.
BUDGET_SEC = 90
FETCH_TIMEOUT = 10

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
    "sitemap": "Sitemap",
}


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
    total = sum(it["weight"] for it in items) or 1
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


def _path_label(url: str) -> str:
    p = urlparse(url).path or "/"
    return p if p != "/" else "/"


def _normalize_page_url(url: str) -> str | None:
    try:
        u = urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    if u.scheme not in ("http", "https") or not u.netloc:
        return None
    if STATIC_EXT.search(u.path or ""):
        return None
    path = u.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Drop fragments and most query noise for dedupe; keep bare path.
    return urlunparse((u.scheme, u.netloc.lower(), path, "", "", ""))


def audit_html(url: str, html: str, *, final_url: str | None = None, include_sitemap: bool = False,
               robots_text: str | None = None, sitemap_found: bool = False) -> dict:
    """Parse HTML and return a friendly scored audit. Pure function for tests."""
    final = final_url or url
    soup = BeautifulSoup(html or "", "html.parser")
    items: list[dict] = []

    if final.lower().startswith("https://"):
        items.append(_item("https", PASS, "The page loads over HTTPS.", final))
    else:
        items.append(_item(
            "https", FAIL, "The final URL is not HTTPS.", final,
            tip="Redirect HTTP to HTTPS so visitors and Google see a secure site.",
        ))

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

    desc = _meta(soup, name="description")
    if not desc:
        items.append(_item("meta_description", FAIL, "No meta description.", tip="Add a clear 1–2 sentence summary (about 50–160 characters)."))
    elif len(desc) < 50:
        items.append(_item("meta_description", WARN, "Meta description is short.", desc, tip="A little more detail helps the snippet in search results."))
    elif len(desc) > 165:
        items.append(_item("meta_description", WARN, f"Meta description is long ({len(desc)} characters).", desc[:120] + "…", tip="Trim to about 150–160 characters."))
    else:
        items.append(_item("meta_description", PASS, "Meta description looks good.", desc))

    h1s = [re.sub(r"\s+", " ", h.get_text(" ", strip=True)) for h in soup.find_all("h1")]
    h1s = [h for h in h1s if h]
    if not h1s:
        items.append(_item("h1", FAIL, "No H1 heading on the page.", tip="Add one clear main heading (H1) that matches the topic."))
    elif len(h1s) > 1:
        items.append(_item("h1", WARN, f"Found {len(h1s)} H1 headings — usually one is enough.", h1s[0], tip="Keep a single main H1; use H2/H3 for sections."))
    else:
        items.append(_item("h1", PASS, "One clear H1 heading.", h1s[0]))

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

    robots = (_meta(soup, name="robots") or "").lower()
    if "noindex" in robots:
        items.append(_item("meta_robots", FAIL, "Page is set to noindex — search engines should skip it.", robots, tip="Remove noindex if this page should appear in Google."))
    elif "nofollow" in robots:
        items.append(_item("meta_robots", WARN, "Page uses nofollow.", robots, tip="Only keep nofollow if you intentionally don't want links followed."))
    else:
        items.append(_item("meta_robots", PASS, "Page can be indexed.", robots or "index, follow (default)"))

    vp = _meta(soup, name="viewport")
    if not vp:
        items.append(_item("viewport", FAIL, "No mobile viewport meta tag.", tip="Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">."))
    elif "width" not in vp.lower():
        items.append(_item("viewport", WARN, "Viewport tag looks incomplete.", vp))
    else:
        items.append(_item("viewport", PASS, "Mobile viewport is set.", vp))

    html_tag = soup.find("html")
    lang = (html_tag.get("lang") or "").strip() if html_tag else ""
    if not lang:
        items.append(_item("html_lang", WARN, "No language set on <html>.", tip="Add lang=\"en\" or lang=\"en-IN\" (or your language) on the <html> tag."))
    else:
        items.append(_item("html_lang", PASS, "Page language is set.", lang))

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

    tw = _meta(soup, name="twitter:card") or _meta(soup, prop="twitter:card")
    if tw:
        items.append(_item("twitter_card", PASS, "Twitter/X card type is set.", tw))
    else:
        items.append(_item("twitter_card", WARN, "No twitter:card meta tag.", tip="Add twitter:card (e.g. summary_large_image) for nicer previews on X."))

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

    charset_tag = soup.find("meta", attrs={"charset": True}) or soup.find("meta", attrs={"http-equiv": re.compile("content-type", re.I)})
    if charset_tag:
        items.append(_item("charset", PASS, "Character encoding is declared."))
    else:
        items.append(_item("charset", WARN, "No charset meta tag.", tip="Add <meta charset=\"utf-8\"> near the top of <head>."))

    if include_sitemap:
        sm_link = soup.find("link", attrs={"rel": lambda v: v and "sitemap" in str(v).lower()})
        robots_sm = bool(robots_text and re.search(r"(?im)^sitemap:\s*\S+", robots_text))
        if sm_link or robots_sm or sitemap_found:
            items.append(_item("sitemap", PASS, "Sitemap is available for discovery."))
        else:
            items.append(_item(
                "sitemap", WARN, "No sitemap found in robots.txt or on this page.",
                tip="Publish /sitemap.xml and list it in robots.txt with a Sitemap: line.",
            ))

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
        "path": _path_label(final),
        "checked_at": now(),
        "score": score,
        "grade": _grade(score),
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "checks": items,
        "improvements": improvements,
        "summary": _summary(score, failed, warned),
        "title": title[:120] if title else None,
    }


def _summary(score: int, failed: int, warned: int) -> str:
    if failed == 0 and warned == 0:
        return "Looking solid — nothing urgent to fix on this page."
    if failed == 0:
        return f"Score {score}. A few easy tweaks could make this page clearer in search."
    if score >= 70:
        return f"Score {score}. Fix the {failed} important issue{'s' if failed != 1 else ''} below when you can."
    return f"Score {score}. Start with the red items — they matter most for search and sharing."


def _site_summary(score: int, pages: int, failed_pages: int, failed_checks: int) -> str:
    if pages <= 1:
        return _summary(score, failed_checks, 0)
    if failed_checks == 0 and failed_pages == 0:
        return f"Looking solid across {pages} pages — nothing urgent to fix."
    if failed_pages:
        return f"Score {score} across {pages} pages. {failed_pages} page{'s' if failed_pages != 1 else ''} need attention."
    return f"Score {score} across {pages} pages. A few easy tweaks would help search and sharing."


def _extract_links(html: str, base: str, root: str) -> list[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    ranked: list[tuple[int, int, str]] = []
    seen: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        abs_url = urljoin(base, href)
        norm = _normalize_page_url(abs_url)
        if not norm or norm in seen:
            continue
        u = urlparse(norm)
        if registrable_domain(u.hostname or "") != root:
            continue
        seen.add(norm)
        text = a.get_text(" ", strip=True)[:60]
        ranked.append((0 if PRIORITY_LINK.search(u.path + " " + text) else 1, len(u.path or ""), norm))
    ranked.sort()
    # Prefer diverse first path segments so we don't only audit /blog/*
    out, groups = [], set()
    for _, _, url in ranked:
        segs = [x for x in urlparse(url).path.split("/") if x]
        key = segs[0] if segs else ""
        if key in groups and len(out) >= 8:
            continue
        groups.add(key)
        out.append(url)
    return out


def _parse_sitemap_locs(xml_text: str) -> tuple[list[str], list[str]]:
    """Return (page_urls, child_sitemap_urls) from sitemap XML."""
    pages, children = [], []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return pages, children
    tag = (root.tag or "").lower()
    is_index = "sitemapindex" in tag
    locs: list[str] = []
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.lower().endswith("loc") and (el.text or "").strip():
            locs.append(el.text.strip())
    if is_index:
        children.extend(locs)
    else:
        for loc in locs:
            if re.search(r"sitemap[^/]*\.xml(\.gz)?$", loc, re.I):
                children.append(loc)
            else:
                pages.append(loc)
    return pages, children


def _fetch_text(url: str, timeout: int = FETCH_TIMEOUT, accept: str = "*/*") -> tuple[str | None, str | None, int | None]:
    """Return (text, final_url, status) or (None, None, status/None) on soft failure."""
    try:
        out = http_request(url, timeout=timeout, headers={"Accept": accept})
        if out.status >= 400:
            return None, out.final_url, out.status
        return out.text, out.final_url, out.status
    except Exception:  # noqa: BLE001
        return None, None, None


def _discover_from_sitemap(origin: str, robots_text: str | None, limit: int, root: str) -> tuple[list[str], list[str]]:
    """Return (normalized page urls, sitemap urls we tried)."""
    sm_urls: list[str] = []
    if robots_text:
        for m in re.finditer(r"(?im)^sitemap:\s*(\S+)", robots_text):
            sm_urls.append(m.group(1).strip())
    for guess in (f"{origin}/sitemap.xml", f"{origin}/sitemap_index.xml"):
        if guess not in sm_urls:
            sm_urls.append(guess)

    found: list[str] = []
    seen_sm: set[str] = set()
    queue = list(sm_urls)
    tried: list[str] = []
    while queue and len(found) < limit:
        sm = queue.pop(0)
        if sm in seen_sm:
            continue
        seen_sm.add(sm)
        tried.append(sm)
        text, _, status = _fetch_text(sm, timeout=8, accept="application/xml,text/xml,*/*;q=0.8")
        if not text or status and status >= 400:
            continue
        # Skip obvious HTML error pages
        if "<html" in text[:200].lower() and "<urlset" not in text.lower() and "<sitemapindex" not in text.lower():
            continue
        pages, children = _parse_sitemap_locs(text)
        for child in children[:10]:
            if child not in seen_sm:
                queue.append(child)
        for p in pages:
            norm = _normalize_page_url(p)
            if not norm:
                continue
            if registrable_domain(urlparse(norm).hostname or "") != root:
                continue
            if norm not in found:
                found.append(norm)
            if len(found) >= limit:
                break
    return found, tried


def discover_pages(home_url: str, home_html: str, home_final: str, robots_text: str | None, limit: int) -> dict:
    """Build an ordered list of pages to audit (homepage first)."""
    root = registrable_domain(urlparse(home_final or home_url).hostname or "")
    origin = f"{urlparse(home_final or home_url).scheme}://{urlparse(home_final or home_url).netloc}"
    home_norm = _normalize_page_url(home_final or home_url) or (home_final or home_url)

    from_sitemap, sitemap_tried = _discover_from_sitemap(origin, robots_text, limit, root)
    from_links = _extract_links(home_html, home_final or home_url, root)

    ordered: list[str] = []
    seen: set[str] = set()

    def add(u: str):
        if u and u not in seen:
            seen.add(u)
            ordered.append(u)

    add(home_norm)
    for u in from_sitemap:
        add(u)
        if len(ordered) >= limit:
            break
    if len(ordered) < limit:
        for u in from_links:
            add(u)
            if len(ordered) >= limit:
                break

    return {
        "urls": ordered[:limit],
        "from_sitemap": len([u for u in ordered if u in set(from_sitemap)]),
        "from_links": len([u for u in ordered if u in set(from_links) and u not in set(from_sitemap) and u != home_norm]),
        "sitemap_found": bool(from_sitemap),
        "sitemap_urls": sitemap_tried[:8],
    }


def _audit_one(url: str, *, include_sitemap: bool, robots_text: str | None, sitemap_found: bool) -> dict:
    t = now()
    try:
        out = http_request(
            url, timeout=FETCH_TIMEOUT,
            headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
        )
        html, final = out.text, out.final_url
        if out.status >= 400 and not ("<html" in html.lower() or "<title" in html.lower()):
            return {
                "url": final,
                "path": _path_label(final),
                "checked_at": t,
                "score": 0,
                "grade": "F",
                "passed": 0,
                "warned": 0,
                "failed": 1,
                "checks": [],
                "improvements": [],
                "summary": f"Could not audit — HTTP {out.status}.",
                "http_status": out.status,
                "error": f"HTTP {out.status}",
            }
        snap = audit_html(
            url, html, final_url=final, include_sitemap=include_sitemap,
            robots_text=robots_text, sitemap_found=sitemap_found,
        )
        snap["http_status"] = out.status
        snap["checked_at"] = t
        snap["response_ms"] = out.elapsed_ms
        return snap
    except Exception as e:  # noqa: BLE001
        kind, msg = classify_exception(e)
        return {
            "url": url,
            "path": _path_label(url),
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


def _aggregate(pages: list[dict], discovery: dict, home_url: str, t) -> dict:
    ok_pages = [p for p in pages if not p.get("error") or p.get("checks")]
    scored = [p for p in pages if isinstance(p.get("score"), int) and p.get("checks")]
    if scored:
        score = round(sum(p["score"] for p in scored) / len(scored))
    else:
        score = 0

    # Prefer homepage checks as the "site checklist" preview; fall back to first page.
    home = next((p for p in pages if p.get("is_home")), pages[0] if pages else None)
    checks = (home or {}).get("checks") or []

    passed = sum(p.get("passed") or 0 for p in pages)
    warned = sum(p.get("warned") or 0 for p in pages)
    failed = sum(p.get("failed") or 0 for p in pages)
    failed_pages = sum(1 for p in pages if (p.get("failed") or 0) > 0 or p.get("error"))

    # Top improvements across the site, worst first, capped.
    rank = {FAIL: 0, WARN: 1}
    imps = []
    for p in pages:
        for imp in p.get("improvements") or []:
            imps.append({
                **imp,
                "path": p.get("path") or _path_label(p.get("url") or ""),
                "url": p.get("url"),
                "page_score": p.get("score"),
            })
    imps.sort(key=lambda x: (rank.get(x.get("status"), 9), x.get("page_score") or 0))
    # Dedupe same issue+path
    seen, improvements = set(), []
    for imp in imps:
        key = (imp.get("id"), imp.get("path"))
        if key in seen:
            continue
        seen.add(key)
        improvements.append(imp)
        if len(improvements) >= 20:
            break

    page_rows = []
    for p in pages:
        page_rows.append({
            "url": p.get("url"),
            "path": p.get("path") or _path_label(p.get("url") or ""),
            "title": p.get("title"),
            "score": p.get("score", 0),
            "grade": p.get("grade", "F"),
            "passed": p.get("passed", 0),
            "warned": p.get("warned", 0),
            "failed": p.get("failed", 0),
            "checks": p.get("checks") or [],
            "improvements": p.get("improvements") or [],
            "summary": p.get("summary"),
            "http_status": p.get("http_status"),
            "error": p.get("error"),
            "is_home": bool(p.get("is_home")),
            "response_ms": p.get("response_ms"),
        })
    # Worst pages first after homepage
    home_row = next((p for p in page_rows if p.get("is_home")), None)
    rest = [p for p in page_rows if not p.get("is_home")]
    rest.sort(key=lambda p: (p.get("score") if p.get("score") is not None else 999, p.get("path") or ""))
    ordered = ([home_row] if home_row else []) + rest

    return {
        "url": (home or {}).get("url") or home_url,
        "checked_at": t,
        "score": score,
        "grade": _grade(score),
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "checks": checks,
        "improvements": improvements,
        "summary": _site_summary(score, len(pages), failed_pages, failed),
        "pages": ordered,
        "pages_checked": len(pages),
        "pages_ok": len(ok_pages),
        "pages_with_issues": failed_pages,
        "discovery": {
            "from_sitemap": discovery.get("from_sitemap", 0),
            "from_links": discovery.get("from_links", 0),
            "sitemap_found": discovery.get("sitemap_found", False),
            "limit": discovery.get("limit"),
        },
        "http_status": (home or {}).get("http_status"),
        "response_ms": (home or {}).get("response_ms"),
    }


def run_seo_audit(site_id) -> dict | None:
    """Discover pages (sitemap + links), audit each, store site snapshot + history."""
    db = get_db()
    site = db.websites.find_one({"_id": site_id})
    if not site or not site.get("seo_enabled", True):
        return None
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    t = now()
    url = site["url"]
    page_limit = max(1, int((limits(ws) or {}).get("seo_pages") or 10))

    try:
        home_out = http_request(
            url, timeout=FETCH_TIMEOUT,
            headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
        )
        home_html, home_final = home_out.text, home_out.final_url
        robots_text = None
        try:
            origin = f"{urlparse(home_final).scheme}://{urlparse(home_final).netloc}"
            rob = http_request(f"{origin}/robots.txt", timeout=6, headers={"Accept": "text/plain,*/*;q=0.8"})
            if rob.status < 400:
                robots_text = rob.text[:50_000]
        except Exception:  # noqa: BLE001
            robots_text = None

        discovery = discover_pages(url, home_html, home_final, robots_text, page_limit)
        discovery["limit"] = page_limit
        urls = discovery["urls"] or [_normalize_page_url(home_final) or home_final]

        pages: list[dict] = []
        t0 = time.time()
        for i, page_url in enumerate(urls):
            if time.time() - t0 > BUDGET_SEC and pages:
                break
            # Reuse already-fetched homepage body for the first URL when it matches.
            if i == 0 and _normalize_page_url(page_url) == _normalize_page_url(home_final):
                if home_out.status >= 400 and not ("<html" in home_html.lower() or "<title" in home_html.lower()):
                    snap = {
                        "url": home_final,
                        "path": _path_label(home_final),
                        "checked_at": t,
                        "score": 0,
                        "grade": "F",
                        "passed": 0,
                        "warned": 0,
                        "failed": 1,
                        "checks": [],
                        "improvements": [],
                        "summary": f"Could not audit — the page returned HTTP {home_out.status}.",
                        "http_status": home_out.status,
                        "error": f"HTTP {home_out.status}",
                        "is_home": True,
                    }
                else:
                    snap = audit_html(
                        url, home_html, final_url=home_final, include_sitemap=True,
                        robots_text=robots_text, sitemap_found=discovery.get("sitemap_found", False),
                    )
                    snap["http_status"] = home_out.status
                    snap["checked_at"] = t
                    snap["response_ms"] = home_out.elapsed_ms
                    snap["is_home"] = True
            else:
                snap = _audit_one(
                    page_url, include_sitemap=False,
                    robots_text=robots_text, sitemap_found=discovery.get("sitemap_found", False),
                )
                snap["is_home"] = False
            pages.append(snap)

        snapshot = _aggregate(pages, discovery, url, t)
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
            "summary": "Could not reach the site to run the SEO audit.",
            "error": msg,
            "error_kind": kind,
            "pages": [],
            "pages_checked": 0,
        }

    ok = snapshot.get("score", 0) >= 60 and not snapshot.get("error")
    critical_fail = any(
        c.get("status") == FAIL and c.get("id") in ("https", "title", "meta_robots")
        for p in (snapshot.get("pages") or [snapshot])
        for c in (p.get("checks") or [])
    )
    # Also treat many failing pages as critical
    if (snapshot.get("pages_with_issues") or 0) >= max(2, (snapshot.get("pages_checked") or 1) // 2):
        critical_fail = True

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
        n = snapshot.get("pages_checked") or 1
        incidents.open_or_update(
            ws,
            key=key,
            source_type="seo",
            source_id=site["_id"],
            website_id=site["_id"],
            client_id=site.get("client_id"),
            severity="minor",
            title=f"SEO needs attention on {host}",
            summary=snapshot.get("summary") or f"SEO score {snapshot.get('score', 0)} across {n} pages",
            evidence={"type": "check_result", "ref_id": rid, "summary": snapshot.get("summary")},
        )
    elif ok:
        incidents.auto_resolve(ws, key, "SEO audit looks healthy again.")

    return snapshot
