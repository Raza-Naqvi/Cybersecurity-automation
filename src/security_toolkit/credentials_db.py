"""MongoDB-backed store for test-account credentials, keyed by target
name + label (e.g. "IDOR_USER_A"). Scales across many targets — each
one's test accounts live in their own document, looked up by name,
instead of one flat .env that gets overwritten every time a new target
is provisioned.

This is the toolkit's OWN storage — a local MongoDB instance or your own
private Atlas cluster, set via `MONGODB_URI` in .env (default
`mongodb://localhost:27017`; an Atlas URI looks like
`mongodb+srv://user:pass@cluster-host/...` — needs the `dnspython`
package installed, already in requirements.txt). It never touches the
app under test's database; storing credentials here doesn't violate the
black-box engagement model, same as .env didn't.

Never commit real credentials: this collection holds disposable test
account passwords, not real users' — but still, don't point `MONGODB_URI`
at a shared/production Mongo instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from security_toolkit.config import get_mongo_database

COLLECTION_NAME = "test_account_credentials"


@dataclass(frozen=True)
class StoredCredentials:
    target_name: str
    label: str
    username: str
    password: str


def _doc_id(target_name: str, label: str) -> str:
    return f"{target_name}:{label}"


def _collection(uri: str | None = None, db_name: str | None = None) -> Any:
    return get_mongo_database(uri, db_name)[COLLECTION_NAME]


def save_credentials(
    target_name: str, label: str, username: str, password: str, uri: str | None = None
) -> None:
    """Insert or replace one target+label's credentials."""
    collection = _collection(uri)
    collection.update_one(
        {"_id": _doc_id(target_name, label)},
        {
            "$set": {
                "target_name": target_name,
                "label": label,
                "username": username,
                "password": password,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        },
        upsert=True,
    )


def load_credentials(target_name: str, label: str, uri: str | None = None) -> StoredCredentials | None:
    collection = _collection(uri)
    doc = collection.find_one({"_id": _doc_id(target_name, label)})
    if doc is None:
        return None
    return StoredCredentials(
        target_name=doc["target_name"], label=doc["label"], username=doc["username"], password=doc["password"]
    )


def delete_credentials(target_name: str, label: str | None = None, uri: str | None = None) -> int:
    """Delete one label's credentials, or every label for a target if
    `label` is None. Returns the number of documents removed.
    """
    collection = _collection(uri)
    if label is None:
        result = collection.delete_many({"target_name": target_name})
    else:
        result = collection.delete_one({"_id": _doc_id(target_name, label)})
    return result.deleted_count


def list_credentials(target_name: str | None = None, uri: str | None = None) -> tuple[StoredCredentials, ...]:
    """List every stored credential, or just one target's. Includes
    passwords — for internal/CLI use only, never paste this into a
    shared channel.
    """
    collection = _collection(uri)
    query = {} if target_name is None else {"target_name": target_name}
    docs = collection.find(query).sort([("target_name", 1), ("label", 1)])
    return tuple(
        StoredCredentials(
            target_name=doc["target_name"], label=doc["label"], username=doc["username"], password=doc["password"]
        )
        for doc in docs
    )
