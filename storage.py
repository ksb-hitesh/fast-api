"""MongoDB mirror of the local out/ tree.

Render's free tier has no persistent disk: the filesystem is wiped on every deploy,
restart and idle spin-down. takedown.py and discover.py keep writing plain files
exactly as they do on the CLI; this module mirrors that tree into MongoDB so the
RFC-3161 evidence survives a restart.

One document per file, keyed on the repo-relative path. A saved page is a few hundred
KB, far under the 16MB BSON cap, so there is no GridFS here.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).parent
SYNCED = ("out", "urls.txt", "config.json")

_client = None


def enabled() -> bool:
    return bool(os.environ.get("MONGODB_URI"))


def _coll():
    global _client
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        return None
    if _client is None:
        from pymongo import MongoClient
        _client = MongoClient(uri, serverSelectionTimeoutMS=15000,
                              connectTimeoutMS=15000, retryWrites=True)
    return _client[os.environ.get("MONGODB_DB", "takedown")]["files"]


def _local_files() -> list[Path]:
    found: list[Path] = []
    for name in SYNCED:
        p = ROOT / name
        if p.is_dir():
            found += sorted(f for f in p.rglob("*") if f.is_file())
        elif p.is_file():
            found.append(p)
    return found


def _safe(key: str) -> Path | None:
    """Resolve a stored key under ROOT, or None if it tries to escape."""
    p = (ROOT / key).resolve()
    return p if p.is_relative_to(ROOT.resolve()) else None


def push() -> int:
    """Upload every file whose contents changed. Returns how many were written."""
    c = _coll()
    if c is None:
        return 0
    from bson.binary import Binary

    have = {d["_id"]: d.get("sha") for d in c.find({}, {"sha": 1})}
    n = 0
    # ponytail: one upsert per changed file. A run touches a handful of files, so
    # bulk_write would be buying nothing. Batch it if a case ever grows to thousands.
    for f in _local_files():
        data = f.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        key = f.relative_to(ROOT).as_posix()
        if have.get(key) == sha:
            continue
        c.replace_one({"_id": key},
                      {"_id": key, "sha": sha, "data": Binary(data)}, upsert=True)
        n += 1
    return n


def pull() -> int:
    """Restore every stored file to disk, overwriting local copies."""
    c = _coll()
    if c is None:
        return 0
    n = 0
    for doc in c.find({}):
        p = _safe(doc["_id"])
        if p is None:
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(bytes(doc["data"]))
        n += 1
    return n


def forget(key: str) -> None:
    """Drop one file from the mirror (used when urls.txt rows are removed)."""
    c = _coll()
    if c is not None:
        c.delete_one({"_id": key})
