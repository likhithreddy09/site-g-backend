"""Durable screenshot/artifact storage via MongoDB GridFS.

Local files under STORAGE_DIR are a working cache for Playwright/Pillow. On Railway the
container filesystem is ephemeral, so every artifact is also written to GridFS and served
from there after redeploys/restarts.
"""
from __future__ import annotations

import mimetypes
import os

from gridfs import GridFS
from gridfs.errors import NoFile

from ..config import Config
from ..db import get_db

_BUCKET = "artifacts"


def _fs() -> GridFS:
    return GridFS(get_db(), collection=_BUCKET)


def abs_path(rel_path: str) -> str:
    return os.path.join(Config.STORAGE_DIR, "artifacts", rel_path)


def put_file(rel_path: str, src_path: str | None = None, data: bytes | None = None,
             content_type: str | None = None) -> str:
    """Persist an artifact to GridFS. Provide either src_path or data."""
    if data is None:
        if not src_path:
            raise ValueError("src_path or data required")
        with open(src_path, "rb") as f:
            data = f.read()
    if not content_type:
        content_type = mimetypes.guess_type(rel_path)[0] or "application/octet-stream"
    fs = _fs()
    for existing in fs.find({"filename": rel_path}):
        fs.delete(existing._id)
    fs.put(data, filename=rel_path, content_type=content_type, metadata={"rel": rel_path})
    return rel_path


def get_bytes(rel_path: str) -> bytes | None:
    fs = _fs()
    try:
        return fs.get_last_version(filename=rel_path).read()
    except NoFile:
        local = abs_path(rel_path)
        if os.path.isfile(local):
            with open(local, "rb") as f:
                return f.read()
        return None


def exists(rel_path: str) -> bool:
    if _fs().exists({"filename": rel_path}):
        return True
    return os.path.isfile(abs_path(rel_path))


def ensure_local(rel_path: str) -> str:
    """Return an absolute local path, hydrating from GridFS if the file was wiped."""
    path = abs_path(rel_path)
    if os.path.isfile(path):
        return path
    data = get_bytes(rel_path)
    if data is None:
        raise FileNotFoundError(rel_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def copy(src_rel: str, dst_rel: str) -> str:
    data = get_bytes(src_rel)
    if data is None:
        raise FileNotFoundError(src_rel)
    dst_abs = abs_path(dst_rel)
    os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
    with open(dst_abs, "wb") as f:
        f.write(data)
    put_file(dst_rel, data=data)
    return dst_rel


def delete(rel_path: str) -> None:
    fs = _fs()
    for existing in fs.find({"filename": rel_path}):
        fs.delete(existing._id)
    local = abs_path(rel_path)
    if os.path.isfile(local):
        try:
            os.remove(local)
        except OSError:
            pass


def delete_prefix(prefix: str, keep: set[str] | None = None, older_than_ts: float | None = None) -> int:
    """Delete GridFS files under a workspace prefix (and matching local files)."""
    keep = keep or set()
    removed = 0
    fs = _fs()
    for grid in fs.find({"filename": {"$regex": f"^{prefix}"}}):
        name = grid.filename
        base = os.path.basename(name)
        if base in keep or name in keep:
            continue
        if older_than_ts is not None:
            upload = getattr(grid, "upload_date", None)
            if upload and upload.timestamp() >= older_than_ts:
                continue
        fs.delete(grid._id)
        removed += 1
        local = abs_path(name)
        if os.path.isfile(local):
            try:
                os.remove(local)
            except OSError:
                pass
    return removed


def open_stream(rel_path: str):
    """Return (file-like, content_type, length) for HTTP serving, or None."""
    fs = _fs()
    try:
        grid = fs.get_last_version(filename=rel_path)
        ctype = getattr(grid, "content_type", None) or mimetypes.guess_type(rel_path)[0] or "application/octet-stream"
        return grid, ctype, grid.length
    except NoFile:
        local = abs_path(rel_path)
        if not os.path.isfile(local):
            return None
        ctype = mimetypes.guess_type(rel_path)[0] or "application/octet-stream"
        f = open(local, "rb")
        return f, ctype, os.path.getsize(local)
