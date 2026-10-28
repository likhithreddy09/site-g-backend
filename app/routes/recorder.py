from flask import Blueprint, g, jsonify

from ..plans import quota_left
from ..security import normalize_url, require
from ..services import recorder
from ..utils import ApiError, clamp_int
from . import body

bp = Blueprint("recorder", __name__, url_prefix="/api/recorder")


@bp.post("/sessions")
@require("member")
def start_session():
    if quota_left(g.ws, "browser_seconds", "browser_minutes", 60) <= 0:
        raise ApiError("Browser-test minutes for this month are used up", 402, "plan_limit")
    url = normalize_url(body().get("url", ""))
    s, state = recorder.start(g.ws, g.user["_id"], url)
    return jsonify({"session_id": s.id, "start_url": url, "state": state}), 201


@bp.get("/sessions/<sid>")
@require("member")
def session_state(sid):
    return jsonify({"state": recorder.refresh(recorder.get(sid, g.ws_id))})


@bp.post("/sessions/<sid>/inspect")
@require("member")
def inspect(sid):
    data = body()
    x, y = clamp_int(data.get("x"), 0, recorder.VIEW["width"], 0), clamp_int(data.get("y"), 0, recorder.VIEW["height"], 0)
    return jsonify(recorder.inspect(recorder.get(sid, g.ws_id), x, y))


@bp.post("/sessions/<sid>/action")
@require("member")
def action(sid):
    return jsonify(recorder.perform(recorder.get(sid, g.ws_id), body()))


@bp.delete("/sessions/<sid>")
@require("member")
def close(sid):
    try:
        recorder.get(sid, g.ws_id).close()
    except ApiError:
        pass
    return jsonify({"ok": True})
