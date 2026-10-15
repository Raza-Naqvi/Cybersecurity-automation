"""MongoDB-backed store for authorized targets (what used to live in a
local, gitignored `config/scope.json` on each machine). This is the
toolkit's OWN storage — same `MONGODB_URI` as `credentials_db.py` and
`report_index.py`, never the target app's database — so every machine
pointed at the same Mongo instance sees the same authorized-target
list, instead of each needing its own local file kept in sync by hand.

Keyed by target name (`_id`), same one-document-per-entity shape as
`credentials_db.py`.
"""

from __future__ import annotations

from typing import Any

from security_toolkit.config import get_mongo_database

COLLECTION_NAME = "scope_targets"


def _collection(uri: str | None = None, db_name: str | None = None) -> Any:
    return get_mongo_database(uri, db_name)[COLLECTION_NAME]


def save_target(target: dict, uri: str | None = None) -> None:
    """Insert or replace one target's scope entry, keyed by its name."""
    if not target.get("name"):
        raise ValueError("target must have a non-empty 'name'")
    collection = _collection(uri)
    collection.replace_one({"_id": target["name"]}, {**target, "_id": target["name"]}, upsert=True)


def load_target(name: str, uri: str | None = None) -> dict | None:
    collection = _collection(uri)
    doc = collection.find_one({"_id": name})
    if doc is None:
        return None
    return {key: value for key, value in doc.items() if key != "_id"}


def delete_target(name: str, uri: str | None = None) -> bool:
    """Returns True if a target was actually removed, False if it wasn't there."""
    collection = _collection(uri)
    result = collection.delete_one({"_id": name})
    return result.deleted_count > 0


def list_all_targets(uri: str | None = None) -> tuple[dict, ...]:
    collection = _collection(uri)
    docs = collection.find({}).sort([("_id", 1)])
    return tuple({key: value for key, value in doc.items() if key != "_id"} for doc in docs)
