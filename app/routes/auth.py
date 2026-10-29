from flask import Blueprint, g, jsonify
from pymongo.errors import DuplicateKeyError

from ..audit import audit
from ..db import get_db
from ..plans import new_trial_fields
from ..security import auth_required, check_password, hash_password, make_token
from ..services import notify
from ..utils import ApiError, now, ser, valid_email
from . import body

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def create_workspace(user: dict, name: str) -> dict:
    db = get_db()
    ws = {
        "name": name.strip()[:80] or "My Agency",
        "owner_id": user["_id"],
        **new_trial_fields(),
        "created_at": now(),
        "branding": {},
        "notifications": {"emails": [user["email"]]},
        "settings": {"ai_enabled": True, "rum_defaults": {"sample_rate": 1.0}},
    }
    ws["_id"] = db.workspaces.insert_one(ws).inserted_id
    db.members.insert_one({"workspace_id": ws["_id"], "user_id": user["_id"], "email": user["email"], "role": "owner",
                           "status": "active", "client_ids": [], "created_at": now()})
    audit("workspace.created", "workspace", ws["_id"], {"name": ws["name"]}, ws_id=ws["_id"])
    return ws


def _workspaces_for(user: dict) -> list[dict]:
    db = get_db()
    out = []
    for m in db.members.find({"user_id": user["_id"], "status": "active"}):
        ws = db.workspaces.find_one({"_id": m["workspace_id"]})
        if ws:
            out.append({"id": str(ws["_id"]), "name": ws["name"], "role": m["role"], "plan": ws.get("plan")})
    return out


def _accept_invites(user: dict) -> None:
    get_db().members.update_many({"email": user["email"], "status": "invited"},
                                 {"$set": {"user_id": user["_id"], "status": "active", "joined_at": now()}})


def _session(user: dict) -> dict:
    return {"token": make_token(user["_id"]), "user": {"id": str(user["_id"]), "email": user["email"], "name": user.get("name")},
            "workspaces": _workspaces_for(user)}


@bp.post("/register")
def register():
    data = body()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip()
    if not valid_email(email):
        raise ApiError("Enter a valid email address", 422)
    if len(password) < 8:
        raise ApiError("Password must be at least 8 characters", 422)
    db = get_db()
    user = {"email": email, "name": name or email.split("@")[0], "password_hash": hash_password(password), "created_at": now()}
    try:
        user["_id"] = db.users.insert_one(user).inserted_id
    except DuplicateKeyError:
        raise ApiError("An account with this email already exists", 409)
    g.user = user
    _accept_invites(user)
    if data.get("workspace_name") or not _workspaces_for(user):
        create_workspace(user, data.get("workspace_name") or f"{user['name']}'s Agency")
    # Welcome mail is best-effort — never block signup if SMTP hiccups.
    try:
        notify.send_welcome_email(user)
    except Exception:  # noqa: BLE001
        pass
    return jsonify(_session(user)), 201


@bp.post("/login")
def login():
    data = body()
    email = (data.get("email") or "").strip().lower()
    user = get_db().users.find_one({"email": email})
    if not user or not check_password(data.get("password") or "", user["password_hash"]):
        raise ApiError("Incorrect email or password", 401)
    g.user = user
    _accept_invites(user)
    get_db().users.update_one({"_id": user["_id"]}, {"$set": {"last_login_at": now()}})
    return jsonify(_session(user))


@bp.get("/me")
@auth_required
def me():
    return jsonify({"user": {"id": str(g.user["_id"]), "email": g.user["email"], "name": g.user.get("name")},
                    "workspaces": _workspaces_for(g.user)})


@bp.patch("/me")
@auth_required
def update_me():
    data = body()
    upd = {}
    if "name" in data:
        upd["name"] = str(data["name"])[:80]
    if data.get("new_password"):
        if not check_password(data.get("current_password") or "", g.user["password_hash"]):
            raise ApiError("Current password is incorrect", 403)
        if len(data["new_password"]) < 8:
            raise ApiError("Password must be at least 8 characters", 422)
        upd["password_hash"] = hash_password(data["new_password"])
    if upd:
        get_db().users.update_one({"_id": g.user["_id"]}, {"$set": upd})
    return jsonify({"ok": True})


@bp.post("/workspaces")
@auth_required
def new_workspace():
    name = body().get("name") or ""
    if not name.strip():
        raise ApiError("Workspace name is required", 422)
    ws = create_workspace(g.user, name)
    return jsonify(ser({"id": ws["_id"], "name": ws["name"], "role": "owner", "plan": ws["plan"]})), 201
