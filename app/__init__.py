import logging
import os

from flask import Flask, abort, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from .config import Config
from .db import init_db
from .security import verify_artifact
from .utils import ApiError


def create_app(start_worker: bool | None = None) -> Flask:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}}, supports_credentials=False,
         allow_headers=["Authorization", "Content-Type", "X-Workspace-Id"])
    init_db()

    from .routes import auth, dashboard, errors, incidents, recorder, reports, testing, websites, workspace
    for mod in (auth, workspace, websites, testing, errors, incidents, reports, dashboard, recorder):
        app.register_blueprint(mod.bp)

    @app.errorhandler(ApiError)
    def api_error(e: ApiError):
        return jsonify({"error": e.message, "code": e.code, **e.extra}), e.status

    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        return jsonify({"error": e.description, "code": e.name.lower().replace(" ", "_")}), e.code

    @app.errorhandler(Exception)
    def unhandled(e: Exception):
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Internal server error", "code": "internal"}), 500

    @app.get("/artifacts/<path:rel>")
    def artifact(rel):
        if ".." in rel or not verify_artifact(rel, request.args.get("exp"), request.args.get("sig")):
            abort(403)
        return send_from_directory(os.path.join(Config.STORAGE_DIR, "artifacts"), rel, max_age=3600)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    if start_worker if start_worker is not None else Config.EMBED_WORKER:
        from . import scheduler
        scheduler.start()
    return app
