"""Stack-trace parsing, cross-browser message normalisation and error fingerprinting."""
import hashlib
import re
from urllib.parse import urlparse

from .checks import registrable_domain

_CHROME = re.compile(r"^\s*at (?:(?P<fn>.+?) \()?(?P<file>(?:https?|file|webpack|chrome-extension|blob|app):.*?|<anonymous>|native):(?P<line>\d+)(?::(?P<col>\d+))?\)?\s*$")
_GECKO = re.compile(r"^\s*(?P<fn>[^@\s]*)@(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?\s*$")
_EXTENSION = re.compile(r"^(chrome|moz|safari(-web)?|ms-browser)-extension:|^webkit-masked-url:", re.I)
_HASH_IN_NAME = re.compile(r"([.\-_~])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{6,}(?=\.(?:m?js|cjs|css)$)")
_VENDOR = re.compile(r"/(node_modules|vendor|vendors|wp-includes/js|jquery|polyfill|framework|webpack-runtime|react-dom)[/.\-]", re.I)

_ERR_PREFIX = re.compile(r"^(Uncaught\s+)?(\(in promise\)\s*)?((Type|Reference|Range|Syntax|Eval|URI)?Error|DOMException)?:?\s*", re.I)


def parse_stack(stack: str) -> list[dict]:
    frames = []
    for raw in (stack or "").split("\n")[:60]:
        m = _CHROME.match(raw) or _GECKO.match(raw)
        if not m:
            continue
        fn = (m.group("fn") or "").replace("async ", "").replace("new ", "").strip() or "?"
        frames.append({"fn": fn[:120], "file": m.group("file")[:400], "line": int(m.group("line")), "col": int(m.group("col") or 0)})
    return frames[:30]


def file_key(url: str) -> str:
    """A deploy-stable name for a script: path without query and without content hashes."""
    try:
        p = urlparse(url)
        path = p.path or url
    except ValueError:
        path = url
    parts = path.rstrip("/").split("/")
    parts[-1] = _HASH_IN_NAME.sub("", parts[-1])
    return "/".join(parts)[-160:]


def annotate(frames: list[dict], site_url: str) -> list[dict]:
    root = registrable_domain(urlparse(site_url).hostname or "")
    for f in frames:
        host = (urlparse(f["file"]).hostname or "") if f["file"].startswith("http") else ""
        f["host"] = host
        f["in_app"] = bool(host) and registrable_domain(host) == root and not _VENDOR.search(f["file"])
    return frames


def is_extension_noise(frames: list[dict], source: str) -> bool:
    if source and _EXTENSION.search(source):
        return True
    return bool(frames) and _EXTENSION.search(frames[0]["file"]) is not None


def canonical_message(message: str) -> str:
    """Collapse browser-specific wording of the same bug into one form, then mask volatile values."""
    m = (message or "").strip()
    m = re.sub(r"^Unhandled rejection:\s*", "", m)
    m = _ERR_PREFIX.sub("", m, count=1)
    tail = lambda s: s.split(".")[-1].strip("'\"")  # noqa: E731
    rules = [
        (r"^Cannot read propert(?:y|ies) of (undefined|null)(?: \(reading '([^']*)'\))?", lambda x: f"read '{x[2] or '?'}' of {x[1]}"),
        (r"^Cannot read property '([^']*)' of (undefined|null)", lambda x: f"read '{x[1]}' of {x[2]}"),
        (r"^(undefined|null) is not an object \(evaluating '([^']*)'\)", lambda x: f"read '{tail(x[2])}' of {x[1]}"),
        (r"^can't access property \"([^\"]*)\", .* is (undefined|null)", lambda x: f"read '{x[1]}' of {x[2]}"),
        (r"^([\w$.\[\]'\"]+) is (undefined|null)$", lambda x: f"read '?' of {x[2]}"),
        (r"^Cannot set propert(?:y|ies) of (undefined|null)(?: \(setting '([^']*)'\))?", lambda x: f"set '{x[2] or '?'}' of {x[1]}"),
        (r"^Can't find variable: ([\w$]+)", lambda x: f"{x[1]} is not defined"),
        (r"^([\w$]+) is not defined", lambda x: f"{x[1]} is not defined"),
        (r"^([\w$.\[\]'\"()]+?) is not a function(?:\..*)?$", lambda x: f"{tail(x[1].replace('()', ''))} is not a function"),
        (r"^Loading (?:CSS )?chunk [\w-]+ failed.*|^Failed to fetch dynamically imported module.*|^ChunkLoadError.*", lambda x: "chunk load failed"),
    ]
    for pat, fmt in rules:
        x = re.match(pat, m)
        if x:
            m = fmt(x)
            break
    m = re.sub(r"https?://[^\s'\")]+", lambda u: f"<url:{urlparse(u.group(0)).hostname}>", m)
    m = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", m, flags=re.I)
    m = re.sub(r"\b[0-9a-f]{12,}\b", "<hex>", m, flags=re.I)
    m = re.sub(r"\d+", "N", m)
    return m[:300]


def fn_key(fn: str) -> str:
    """`Object.renderCart`, `renderCart/<` and `renderCart` are the same function in different browsers."""
    fn = re.sub(r"[/<*]+$|\s*\[as [^\]]+\]$", "", fn or "")
    return fn.split(".")[-1] or "?"


def culprit(frames: list[dict]) -> dict | None:
    for f in frames:
        if f.get("in_app"):
            return f
    return frames[0] if frames else None


def third_party_host(frames: list[dict], source: str, site_url: str) -> str | None:
    """Host of the script that threw, when it isn't the website's own code."""
    root = registrable_domain(urlparse(site_url).hostname or "")
    if any(f.get("in_app") for f in frames[:5]):
        return None
    for url in [f["file"] for f in frames[:3]] + [source]:
        host = urlparse(url).hostname if url and url.startswith("http") else None
        if host and registrable_domain(host) != root:
            return host
    return None


def fingerprint(kind: str, message: str, frames: list[dict], api: dict | None) -> str:
    if kind == "api" and api:
        path = re.sub(r"/[0-9a-f-]{6,}|/\d+", "/:id", api.get("url", ""))
        base = f"api|{api.get('method')}|{path}|{api.get('status')}"
    else:
        c = culprit(frames)
        where = f"{fn_key(c['fn'])}@{file_key(c['file'])}" if c else ""
        base = f"js|{canonical_message(message)}|{where}"
    return hashlib.sha1(base.encode()).hexdigest()
