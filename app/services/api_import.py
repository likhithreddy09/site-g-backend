"""Turn Postman collections, OpenAPI/Swagger specs, HAR files, CSV sheets and cURL commands into API-monitor drafts."""
import base64
import csv
import io
import json
import re
import shlex
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .discovery import STATIC_EXT, TRACKER_HOSTS, _template_path

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
SECRET_HEADER = re.compile(r"^(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|.*secret.*|.*token.*)$", re.I)
SKIP_HEADER = re.compile(r"^(content-length|host|connection|accept-encoding|user-agent|origin|referer|sec-.*|:.*)$", re.I)
VAR = re.compile(r"\{\{\s*([\w.-]+)\s*\}\}")
MAX_ITEMS = 200

CSV_COLUMNS = ["name", "method", "url", "expected_status", "max_response_ms", "check_every_minutes", "headers", "body", "must_contain", "website"]


def _item(name, method, url, headers=None, body="", body_type="json", expected=None, folder="", **extra) -> dict:
    method = (method or "GET").upper()
    pub, sec = {}, {}
    for k, v in (headers or {}).items():
        if not k or SKIP_HEADER.match(k):
            continue
        (sec if SECRET_HEADER.match(k) else pub)[k] = str(v)
    it = {"name": (name or f"{method} {urlparse(url).path or '/'}")[:100], "method": method if method in METHODS else "GET", "url": url.strip(),
          "headers": pub, "secret_headers": sec, "body": body or "", "body_type": body_type, "expected_statuses": expected or [200],
          "folder": folder, "warnings": []}
    if method not in METHODS:
        it["warnings"].append(f"{method} isn't supported — will use GET")
    if it["method"] not in ("GET", "HEAD"):
        it["warnings"].append("Sends a real request on every check")
    it.update({k: v for k, v in extra.items() if v not in (None, "", [])})
    return it


# ------------------------------------------------------------------ Postman

def _pm_url(u) -> str:
    if isinstance(u, str):
        return u
    if not isinstance(u, dict):
        return ""
    if u.get("raw"):
        return u["raw"]
    host = ".".join(u.get("host") or []) if isinstance(u.get("host"), list) else (u.get("host") or "")
    path = "/".join(u.get("path") or []) if isinstance(u.get("path"), list) else (u.get("path") or "")
    q = "&".join(f"{x.get('key')}={x.get('value', '')}" for x in u.get("query") or [] if not x.get("disabled"))
    return f"{u.get('protocol', 'https')}://{host}/{path}" + (f"?{q}" if q else "")


def _pm_auth(auth: dict | None, headers: dict) -> None:
    if not auth or not isinstance(auth, dict):
        return
    kind = auth.get("type")
    vals = {x.get("key"): x.get("value") for x in auth.get(kind) or [] if isinstance(x, dict)} if isinstance(auth.get(kind), list) else {}
    if kind == "bearer":
        headers.setdefault("Authorization", f"Bearer {vals.get('token', '{{token}}')}")
    elif kind == "basic":
        raw = f"{vals.get('username', '')}:{vals.get('password', '')}"
        headers.setdefault("Authorization", "Basic " + (base64.b64encode(raw.encode()).decode() if "{{" not in raw else raw))
    elif kind == "apikey" and vals.get("in", "header") == "header":
        headers.setdefault(vals.get("key") or "x-api-key", vals.get("value") or "")


def _postman(doc: dict) -> tuple[list, dict]:
    variables = {v.get("key"): str(v.get("value") or "") for v in doc.get("variable") or [] if isinstance(v, dict) and v.get("key")}
    out = []

    def walk(items, folder, inherited_auth):
        for it in items or []:
            if len(out) >= MAX_ITEMS:
                return
            if "item" in it:
                walk(it["item"], f"{folder} / {it.get('name')}".strip(" /"), it.get("auth") or inherited_auth)
                continue
            req = it.get("request")
            if not req:
                continue
            if isinstance(req, str):
                req = {"url": req, "method": "GET"}
            headers = {h.get("key"): h.get("value", "") for h in req.get("header") or [] if isinstance(h, dict) and not h.get("disabled")}
            _pm_auth(req.get("auth") or inherited_auth, headers)
            body, body_type = "", "json"
            b = req.get("body") or {}
            if b.get("mode") == "raw":
                body = b.get("raw") or ""
                lang = ((b.get("options") or {}).get("raw") or {}).get("language", "json")
                body_type = "json" if lang == "json" else "text"
            elif b.get("mode") == "urlencoded":
                body = urlencode([(x.get("key"), x.get("value", "")) for x in b.get("urlencoded") or [] if not x.get("disabled")])
                body_type = "form"
            out.append(_item(it.get("name"), req.get("method"), _pm_url(req.get("url")), headers, body, body_type, folder=folder))

    walk(doc.get("item"), "", doc.get("auth"))
    return out, variables


# ------------------------------------------------------------------ OpenAPI / Swagger

def _openapi(doc: dict) -> tuple[list, dict]:
    variables = {}
    if doc.get("swagger"):
        scheme = (doc.get("schemes") or ["https"])[0]
        base = f"{scheme}://{doc['host']}{doc.get('basePath', '')}" if doc.get("host") else "{{baseUrl}}" + doc.get("basePath", "")
    else:
        server = ((doc.get("servers") or [{}])[0] or {})
        base = server.get("url") or "{{baseUrl}}"
        for k, v in (server.get("variables") or {}).items():
            base = base.replace("{" + k + "}", str(v.get("default", "")))
        if base.startswith("/"):
            base = "{{baseUrl}}" + base
    if "{{baseUrl}}" in base:
        variables["baseUrl"] = ""
    out = []
    for path, ops in (doc.get("paths") or {}).items():
        for method, op in (ops or {}).items():
            if method.upper() not in METHODS or not isinstance(op, dict) or len(out) >= MAX_ITEMS:
                continue
            p = re.sub(r"\{([\w.-]+)\}", lambda m: "{{" + m.group(1) + "}}", path)
            for name in re.findall(r"\{\{([\w.-]+)\}\}", p):
                variables.setdefault(name, "")
            codes = sorted(int(c) for c in (op.get("responses") or {}) if str(c).isdigit() and 200 <= int(c) < 400)
            body = ""
            content = ((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}
            if content.get("example") is not None:
                body = json.dumps(content["example"], indent=2)
            elif content.get("examples"):
                first = next(iter(content["examples"].values()), {})
                if isinstance(first, dict) and first.get("value") is not None:
                    body = json.dumps(first["value"], indent=2)
            tags = op.get("tags") or []
            out.append(_item(op.get("summary") or op.get("operationId") or f"{method.upper()} {path}", method, base.rstrip("/") + p,
                             {}, body, "json", codes[:3] or [200], folder=tags[0] if tags else "",
                             needs_auth=bool(op.get("security") or doc.get("security"))))
    return out, variables


# ------------------------------------------------------------------ HAR (browser DevTools export)

def _har(doc: dict) -> tuple[list, dict]:
    out, seen = [], set()
    for e in (doc.get("log") or {}).get("entries") or []:
        req, res = e.get("request") or {}, e.get("response") or {}
        url = req.get("url") or ""
        u = urlparse(url)
        mime = ((res.get("content") or {}).get("mimeType") or "").lower()
        rt = e.get("_resourceType") or ""
        if u.scheme not in ("http", "https") or TRACKER_HOSTS.search(url) or STATIC_EXT.search(u.path):
            continue
        if rt not in ("xhr", "fetch") and "json" not in mime and req.get("method", "GET") == "GET":
            continue
        key = (req.get("method"), u.netloc, _template_path(u.path))
        if key in seen:
            continue
        seen.add(key)
        headers = {h["name"]: h.get("value", "") for h in req.get("headers") or [] if h.get("name")}
        post = req.get("postData") or {}
        body_type = "form" if "form-urlencoded" in (post.get("mimeType") or "") else "json" if "json" in (post.get("mimeType") or "") else "text"
        status = res.get("status")
        out.append(_item(None, req.get("method"), url, headers, post.get("text") or "", body_type, [status] if status and status < 400 else [200]))
        if len(out) >= MAX_ITEMS:
            break
    return out, {}


# ------------------------------------------------------------------ CSV

def _csv(text: str) -> tuple[list, dict]:
    rows = list(csv.DictReader(io.StringIO(text.lstrip("\ufeff"))))
    out = []
    for n, r in enumerate(rows[:MAX_ITEMS], start=2):
        r = {(k or "").strip().lower().replace(" ", "_"): (v or "").strip() for k, v in r.items()}
        url = r.get("url") or r.get("endpoint") or ""
        if not url:
            continue
        headers = {}
        for part in re.split(r"[;\n]", r.get("headers", "")):
            if ":" in part:
                k, v = part.split(":", 1)
                headers[k.strip()] = v.strip()
        codes = [int(c) for c in re.findall(r"\d{3}", r.get("expected_status", ""))] or [200]
        it = _item(r.get("name"), r.get("method") or "GET", url, headers, r.get("body", ""),
                   "json" if r.get("body", "").lstrip().startswith(("{", "[")) else "text", codes, row=n, website=r.get("website", ""))
        if r.get("max_response_ms", "").isdigit():
            it["max_response_ms"] = int(r["max_response_ms"])
        if r.get("check_every_minutes", "").isdigit():
            it["interval_sec"] = int(r["check_every_minutes"]) * 60
        if r.get("must_contain"):
            it["assertions"] = [{"type": "body_contains", "path": "", "op": "contains", "value": r["must_contain"]}]
        out.append(it)
    return out, {}


# ------------------------------------------------------------------ cURL

def parse_curl(cmd: str) -> dict:
    cmd = re.sub(r"\\\s*\n", " ", cmd.strip())
    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        raise ValueError(f"Couldn't read that cURL command ({e})") from e
    if not tokens or tokens[0] != "curl":
        raise ValueError("Paste a command that starts with curl")
    method, url, headers, data, i = None, "", {}, [], 1
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-X", "--request"):
            method, i = nxt.upper(), i + 1
        elif t in ("-H", "--header"):
            if ":" in nxt:
                k, v = nxt.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 1
        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json"):
            data.append(nxt)
            if t == "--json":
                headers.setdefault("Content-Type", "application/json")
            i += 1
        elif t in ("-u", "--user"):
            headers["Authorization"] = "Basic " + base64.b64encode(nxt.encode()).decode()
            i += 1
        elif t == "--url":
            url, i = nxt, i + 1
        elif t in ("-b", "--cookie"):
            headers["Cookie"], i = nxt, i + 1
        elif t in ("-A", "--user-agent", "-o", "--output", "-w", "--write-out", "--connect-timeout", "-m", "--max-time"):
            i += 1
        elif not t.startswith("-") and not url:
            url = t
        i += 1
    if not url:
        raise ValueError("No URL found in the cURL command")
    body = "&".join(data)
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    body_type = "form" if "form-urlencoded" in ctype or (body and not body.lstrip().startswith(("{", "[")) and "=" in body) else "json" if body else "json"
    it = _item(None, method or ("POST" if body else "GET"), url, headers, body, body_type)
    p = urlparse(it["url"])
    if p.query:
        it["query"] = dict(parse_qsl(p.query))
        it["url"] = urlunparse(p._replace(query=""))
    return it


# ------------------------------------------------------------------ entry points

def detect(content: str) -> str:
    s = content.lstrip()
    if s.startswith("curl"):
        return "curl"
    if s.startswith(("{", "[")):
        try:
            doc = json.loads(s)
        except ValueError:
            return "unknown"
        if isinstance(doc, dict):
            if "openapi" in doc or "swagger" in doc:
                return "openapi"
            if "log" in doc and "entries" in (doc.get("log") or {}):
                return "har"
            if "item" in doc or "postman" in json.dumps(doc.get("info") or {}):
                return "postman"
        return "unknown"
    if re.match(r"^(openapi|swagger)\s*:", s, re.M):
        return "openapi_yaml"
    first = s.split("\n", 1)[0].lower()
    if "url" in first and "," in first:
        return "csv"
    return "unknown"


def parse(content: str, fmt: str = "auto") -> dict:
    content = content or ""
    fmt = detect(content) if fmt in ("", "auto") else fmt
    if fmt == "openapi_yaml":
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise ValueError("YAML specs aren't supported here yet — export the spec as JSON and try again") from e
        doc, fmt = yaml.safe_load(content), "openapi"
    elif fmt in ("postman", "openapi", "har"):
        try:
            doc = json.loads(content)
        except ValueError as e:
            raise ValueError(f"That file isn't valid JSON ({e})") from e
    if fmt == "postman":
        items, variables = _postman(doc)
    elif fmt == "openapi":
        items, variables = _openapi(doc)
    elif fmt == "har":
        items, variables = _har(doc)
    elif fmt == "csv":
        items, variables = _csv(content)
    elif fmt == "curl":
        items, variables = [parse_curl(content)], {}
    else:
        raise ValueError("We couldn't recognise this file. Supported: Postman collection (v2/v2.1), OpenAPI / Swagger JSON, HAR, CSV, or a cURL command.")
    for it in items:
        blob = json.dumps([it["url"], it["headers"], it["secret_headers"], it["body"]])
        for name in VAR.findall(blob):
            variables.setdefault(name, "")
    return {"format": fmt, "items": items, "variables": variables}


def apply_variables(item: dict, variables: dict) -> dict:
    def sub(v):
        if isinstance(v, str):
            return VAR.sub(lambda m: str(variables.get(m.group(1), m.group(0))) if variables.get(m.group(1)) not in (None, "") else m.group(0), v)
        if isinstance(v, dict):
            return {sub(k): sub(x) for k, x in v.items()}
        return v
    return {k: (sub(v) if k in ("url", "headers", "secret_headers", "body", "query", "name") else v) for k, v in item.items()}
