"""Find and parse OpenAPI / Swagger specs linked from a crawled website."""
import json
import logging
import re
from urllib.parse import urljoin, urlparse

from .api_import import parse as parse_spec
from .checks import registrable_domain

log = logging.getLogger(__name__)

COMMON_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json", "/v1/openapi.json", "/v2/openapi.json",
    "/docs/openapi.json", "/swagger/v1/swagger.json", "/api-docs", "/v3/api-docs",
)

SPEC_IN_HTML = re.compile(r"""["']([^"']*(?:openapi|swagger)[^"']*\.(?:json|ya?ml))["']""", re.I)
API_DOCS_HREF = re.compile(r"""(?:href|content)=["']([^"']*(?:api-docs|swagger-ui|redoc)[^"']*)["']""", re.I)


def _same(host: str, root: str) -> bool:
    return bool(host) and registrable_domain(host) == root


def candidates_from_html(html: str, base: str) -> list[str]:
    found = []
    for m in SPEC_IN_HTML.finditer(html or ""):
        found.append(urljoin(base, m.group(1)))
    for m in API_DOCS_HREF.finditer(html or ""):
        found.append(urljoin(base, m.group(1)))
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    for path in COMMON_PATHS:
        found.append(origin + path)
    # de-dupe preserving order
    out, seen = [], set()
    for u in found:
        u = u.split("#")[0]
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def template_path(path: str) -> str:
    id_seg = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[A-Za-z0-9_-]{32,})$", re.I)
    parts = [("{id}" if id_seg.match(p) else p) for p in path.split("/")]
    return "/".join(parts) or "/"


def fetch_specs(ctx, urls: list[str], root: str, limit: int = 80) -> list[dict]:
    """Return discovery-shaped endpoint dicts from OpenAPI specs reachable on this site."""
    out, tried = [], set()
    for raw in urls:
        if len(out) >= limit:
            break
        u = raw.split("#")[0]
        host = urlparse(u).hostname or ""
        if u in tried or not _same(host, root):
            continue
        tried.add(u)
        page = ctx.new_page()
        try:
            resp = page.goto(u, wait_until="domcontentloaded", timeout=12000)
            if not resp or resp.status >= 400:
                continue
            text = ""
            try:
                body = resp.body().decode("utf-8", "replace")
                if body.strip()[:1] in "{[" or body.lstrip().startswith(("openapi", "swagger", "---")):
                    text = body
            except Exception:  # noqa: BLE001
                text = page.content()
            if not text or len(text) < 20:
                continue
            # HTML swagger-ui pages aren't specs — skip unless we already got JSON/YAML
            if "<html" in text[:200].lower() and "openapi" not in text[:500].lower() and '"paths"' not in text[:2000]:
                continue
            parsed = parse_spec(text, "auto")
            if parsed.get("format") not in ("openapi",):
                continue
            for item in parsed.get("items") or []:
                method = (item.get("method") or "GET").upper()
                url = item.get("url") or ""
                hu = urlparse(url)
                if not url.startswith("http") or not _same(hu.hostname or "", root):
                    # Relative servers sometimes resolve to example.com — skip foreign hosts
                    continue
                path = template_path(hu.path or "/")
                key = f"{method} {hu.scheme}://{hu.netloc}{path}"
                out.append({
                    "key": key, "method": method, "url": f"{hu.scheme}://{hu.netloc}{path}", "host": hu.netloc,
                    "path": path, "templated": path != (hu.path or "/"),
                    "query_params": list((item.get("query") or {}).keys())[:15],
                    "statuses": [200], "count": 1, "pages": [u], "max_ms": 0, "content_type": "application/json",
                    "json_keys": [], "auth_required": bool((item.get("secret_headers") or {}) or (item.get("headers") or {}).get("Authorization")),
                    "sample_query": item.get("query") or {}, "source": "openapi",
                    "name_hint": (item.get("name") or "")[:120],
                })
                if len(out) >= limit:
                    break
        except Exception:  # noqa: BLE001
            log.debug("openapi fetch failed for %s", u, exc_info=True)
        finally:
            page.close()
    return out
