"""API server. Set EMBED_WORKER=false and run worker.py separately in production."""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5050")), debug=False, threaded=True, use_reloader=False)
