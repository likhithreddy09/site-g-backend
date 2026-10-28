"""Standalone monitoring worker, independent of dashboard/API availability."""
import signal
import threading

from app import scheduler
from app.db import init_db

if __name__ == "__main__":
    init_db()
    scheduler.start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
