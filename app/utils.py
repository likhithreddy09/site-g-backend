import re
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: str | None = None, extra: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code or "error"
        self.extra = extra or {}


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def oid(value: Any, field: str = "id") -> ObjectId:
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        raise ApiError(f"Invalid {field}", 400)


def maybe_oid(value: Any) -> ObjectId | None:
    if value in (None, "", "null"):
        return None
    return oid(value)


def ser(value: Any) -> Any:
    """Recursively convert Mongo documents into JSON-safe structures."""
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return aware(value).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "_id":
                out["id"] = str(v)
            elif k in ("password_hash", "secret_headers_enc"):
                continue
            else:
                out[k] = ser(v)
        return out
    if isinstance(value, (list, tuple)):
        return [ser(v) for v in value]
    return value


def token(prefix: str = "", n: int = 24) -> str:
    return prefix + secrets.token_urlsafe(n)


def parse_dt(value: str | None, default: datetime | None = None) -> datetime | None:
    if not value:
        return default
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return aware(dt)
    except ValueError:
        raise ApiError(f"Invalid date: {value}")


def clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(email: str) -> bool:
    return bool(email and EMAIL_RE.match(email))


def days_ago(n: int) -> datetime:
    return now() - timedelta(days=n)
