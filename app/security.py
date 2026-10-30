import base64
import hashlib
import hmac
import ipaddress
import re
import socket
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse, urlunparse

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from flask import g, request

from .config import Config
from .db import get_db
from .utils import ApiError, now, oid

ROLE_RANK = {"client": 0, "member": 1, "admin": 2, "owner": 3}

# ---------------------------------------------------------------- passwords / tokens


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def make_token(user_id) -> str:
    payload = {"sub": str(user_id), "iat": now(), "exp": now() + timedelta(hours=Config.JWT_TTL_HOURS)}
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")


def _current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError("Authentication required", 401, "unauthenticated")
    try:
        payload = jwt.decode(header[7:], Config.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise ApiError("Session expired or invalid", 401, "unauthenticated")
    user = get_db().users.find_one({"_id": oid(payload["sub"])})
    if not user:
        raise ApiError("User not found", 401, "unauthenticated")
    return user


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        g.user = _current_user()
        return fn(*args, **kwargs)

    return wrapper


def require(role: str = "client", *, allow_when_locked: bool = False):
    """Authenticate the user and resolve the active workspace from X-Workspace-Id.

    Mutating requests on a trial-locked workspace are blocked unless allow_when_locked=True
    (used for billing checkout so locked users can still upgrade).
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from .plans import require_unlocked

            g.user = _current_user()
            ws_id = request.headers.get("X-Workspace-Id") or request.args.get("workspace_id")
            if not ws_id:
                raise ApiError("Workspace not selected", 400, "no_workspace")
            db = get_db()
            member = db.members.find_one({"workspace_id": oid(ws_id), "user_id": g.user["_id"], "status": "active"})
            if not member:
                raise ApiError("You do not have access to this workspace", 403, "forbidden")
            if ROLE_RANK.get(member["role"], 0) < ROLE_RANK[role]:
                raise ApiError("Your role does not permit this action", 403, "forbidden")
            g.member = member
            g.role = member["role"]
            g.ws = db.workspaces.find_one({"_id": member["workspace_id"]})
            g.ws_id = g.ws["_id"]
            if (
                not allow_when_locked
                and request.method not in ("GET", "HEAD", "OPTIONS")
            ):
                require_unlocked(g.ws)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def client_scope() -> dict:
    """Extra Mongo filter restricting client-role members to their assigned clients."""
    if g.get("role") == "client":
        return {"client_id": {"$in": g.member.get("client_ids", [])}}
    return {}


# ---------------------------------------------------------------- secret encryption


def _fernet() -> Fernet:
    key = Config.ENCRYPTION_KEY
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(Config.SECRET_KEY.encode()).digest()).decode()
    return Fernet(key.encode())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return ""


# ---------------------------------------------------------------- signed artifact URLs


def sign_artifact(rel_path: str | None, ttl: int = 7 * 24 * 3600) -> str | None:
    if not rel_path:
        return None
    exp = int(time.time()) + ttl
    sig = hmac.new(Config.SECRET_KEY.encode(), f"{rel_path}:{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{Config.PUBLIC_API_URL}/artifacts/{rel_path}?exp={exp}&sig={sig}"


def verify_artifact(rel_path: str, exp: str, sig: str) -> bool:
    try:
        if int(exp) < time.time():
            return False
    except (TypeError, ValueError):
        return False
    expected = hmac.new(Config.SECRET_KEY.encode(), f"{rel_path}:{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(expected, sig or "")


# ---------------------------------------------------------------- SSRF protection

_BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata", "instance-data"}
_dns_cache: dict[str, tuple[float, list[str]]] = {}


def resolve_host(host: str) -> list[str]:
    cached = _dns_cache.get(host)
    if cached and cached[0] > time.time():
        return cached[1]
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips = sorted({i[4][0] for i in infos})
    _dns_cache[host] = (time.time() + 60, ips)
    return ips


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+", re.I)


def is_private_or_local_url(url: str) -> bool:
    """True for localhost / LAN / link-local URLs — never surface these as visitor errors.

    Also accepts a free-form message that embeds such a URL (e.g. Failed to load resource: …).
    """
    raw = str(url or "").strip()
    if not raw:
        return False
    candidates = [raw]
    candidates.extend(_URL_IN_TEXT.findall(raw))
    for cand in candidates:
        try:
            host = (urlparse(cand).hostname or "").lower().strip("[]")
        except ValueError:
            continue
        if not host:
            continue
        if host in _BLOCKED_HOSTS or host.endswith((".localhost", ".internal", ".local")):
            return True
        try:
            if not is_public_ip(host):
                return True
        except ValueError:
            continue
    return False


def check_host_allowed(host: str) -> tuple[bool, str | None]:
    if not host:
        return False, "Missing host"
    host = host.strip("[]").lower()
    if Config.ALLOW_PRIVATE_TARGETS:
        return True, None
    if host in _BLOCKED_HOSTS or host.endswith(".localhost") or host.endswith(".internal") or host.endswith(".local"):
        return False, "Internal hostnames cannot be monitored"
    try:
        ips = [host] if _looks_like_ip(host) else resolve_host(host)
    except socket.gaierror:
        return False, "DNS lookup failed"
    for ip in ips:
        if not is_public_ip(ip):
            return False, f"Target resolves to a non-public address ({ip})"
    return True, None


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_target(url: str) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Malformed URL"
    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https URLs are supported"
    if parsed.username or parsed.password:
        return False, "Credentials in URLs are not allowed"
    if parsed.port and parsed.port not in (80, 443, 8080, 8443) and not Config.ALLOW_PRIVATE_TARGETS:
        return False, "Only standard web ports are allowed"
    return check_host_allowed(parsed.hostname or "")


URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.I)


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    if not URL_RE.match(raw):
        raise ApiError("Enter a valid public URL, e.g. https://example.com", 422, "invalid_url")
    p = urlparse(raw)
    if not p.hostname or "." not in p.hostname and not Config.ALLOW_PRIVATE_TARGETS:
        raise ApiError("Enter a valid public URL with a domain name", 422, "invalid_url")
    netloc = p.hostname.lower() + (f":{p.port}" if p.port else "")
    path = p.path or "/"
    return urlunparse((p.scheme.lower(), netloc, path, "", p.query, ""))


# ---------------------------------------------------------------- redaction

_REDACTIONS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[jwt]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [redacted]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|auth|session|sig|signature|key)=([^&\s\"']+)"), r"\1=[redacted]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[email]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[number]"),
    (re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{8,}\b"), "[key]"),
]


def redact(text):
    if not isinstance(text, str):
        return text
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def strip_query(url: str) -> str:
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except ValueError:
        return url[:300]
