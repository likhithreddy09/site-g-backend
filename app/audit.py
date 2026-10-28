from flask import g, has_request_context, request

from .db import get_db
from .utils import now


def audit(action: str, target_type: str, target_id=None, details: dict | None = None, ws_id=None) -> None:
    user = g.get("user") if has_request_context() else None
    get_db().audit_events.insert_one({
        "workspace_id": ws_id or (g.get("ws_id") if has_request_context() else None),
        "actor_id": user["_id"] if user else None,
        "actor_email": user["email"] if user else "system",
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
        "ip": request.remote_addr if has_request_context() else None,
        "at": now(),
    })
