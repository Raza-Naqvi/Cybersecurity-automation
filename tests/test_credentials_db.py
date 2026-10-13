"""Tests for the MongoDB-backed credential store. No real MongoDB needed
— `_collection` is patched with a tiny in-memory fake that implements
just the pymongo calls this module actually makes (update_one, find_one,
delete_one, delete_many, find().sort()).
"""

from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.credentials_db import delete_credentials, list_credentials, load_credentials, save_credentials


class _FakeCursor:
    def __init__(self, docs: list[dict]):
        self._docs = docs

    def sort(self, _keys):
        return iter(sorted(self._docs, key=lambda d: (d["target_name"], d["label"])))


class _FakeCollection:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    def update_one(self, filter_, update, upsert=False):
        doc_id = filter_["_id"]
        if doc_id not in self.docs and not upsert:
            return
        doc = self.docs.get(doc_id, {"_id": doc_id})
        doc.update(update["$set"])
        self.docs[doc_id] = doc

    def find_one(self, filter_):
        return self.docs.get(filter_["_id"])

    def delete_one(self, filter_):
        existed = filter_["_id"] in self.docs
        self.docs.pop(filter_["_id"], None)
        result = MagicMock()
        result.deleted_count = 1 if existed else 0
        return result

    def delete_many(self, filter_):
        target_name = filter_["target_name"]
        to_remove = [doc_id for doc_id, doc in self.docs.items() if doc["target_name"] == target_name]
        for doc_id in to_remove:
            del self.docs[doc_id]
        result = MagicMock()
        result.deleted_count = len(to_remove)
        return result

    def find(self, filter_):
        if not filter_:
            matched = list(self.docs.values())
        else:
            matched = [doc for doc in self.docs.values() if doc.get("target_name") == filter_.get("target_name")]
        return _FakeCursor(matched)


@pytest.fixture
def fake_collection():
    collection = _FakeCollection()
    with patch("security_toolkit.credentials_db._collection", return_value=collection):
        yield collection


def test_save_and_load_credentials_roundtrip(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "a@test.com", "pw-a")
    result = load_credentials("cheerlytics", "IDOR_USER_A")

    assert result.username == "a@test.com"
    assert result.password == "pw-a"
    assert result.target_name == "cheerlytics"
    assert result.label == "IDOR_USER_A"


def test_load_credentials_returns_none_when_absent(fake_collection):
    assert load_credentials("cheerlytics", "IDOR_USER_A") is None


def test_save_credentials_overwrites_existing(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "old@test.com", "old-pw")
    save_credentials("cheerlytics", "IDOR_USER_A", "new@test.com", "new-pw")

    result = load_credentials("cheerlytics", "IDOR_USER_A")
    assert result.username == "new@test.com"
    assert result.password == "new-pw"


def test_different_targets_coexist(fake_collection):
    save_credentials("site-a", "IDOR_USER_A", "a1@test.com", "pw1")
    save_credentials("site-b", "IDOR_USER_A", "a2@test.com", "pw2")

    assert load_credentials("site-a", "IDOR_USER_A").username == "a1@test.com"
    assert load_credentials("site-b", "IDOR_USER_A").username == "a2@test.com"


def test_delete_credentials_single_label(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "a@test.com", "pw")
    save_credentials("cheerlytics", "IDOR_USER_B", "b@test.com", "pw")

    removed = delete_credentials("cheerlytics", "IDOR_USER_A")

    assert removed == 1
    assert load_credentials("cheerlytics", "IDOR_USER_A") is None
    assert load_credentials("cheerlytics", "IDOR_USER_B") is not None


def test_delete_credentials_all_labels_for_target(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "a@test.com", "pw")
    save_credentials("cheerlytics", "IDOR_USER_B", "b@test.com", "pw")
    save_credentials("other-site", "IDOR_USER_A", "x@test.com", "pw")

    removed = delete_credentials("cheerlytics")

    assert removed == 2
    assert load_credentials("cheerlytics", "IDOR_USER_A") is None
    assert load_credentials("cheerlytics", "IDOR_USER_B") is None
    assert load_credentials("other-site", "IDOR_USER_A") is not None


def test_list_credentials_filters_by_target(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "a@test.com", "pw")
    save_credentials("other-site", "IDOR_USER_A", "x@test.com", "pw")

    results = list_credentials("cheerlytics")

    assert len(results) == 1
    assert results[0].target_name == "cheerlytics"


def test_list_credentials_without_target_returns_all(fake_collection):
    save_credentials("cheerlytics", "IDOR_USER_A", "a@test.com", "pw")
    save_credentials("other-site", "IDOR_USER_A", "x@test.com", "pw")

    results = list_credentials()

    assert len(results) == 2
