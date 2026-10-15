"""Tests for the MongoDB-backed scope store. No real MongoDB needed —
`_collection` is patched with a tiny in-memory fake that implements
just the pymongo calls this module actually makes (replace_one,
find_one, delete_one, find().sort()).
"""

from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.scope_db import delete_target, list_all_targets, load_target, save_target


class _FakeCursor:
    def __init__(self, docs: list[dict]):
        self._docs = docs

    def sort(self, _keys):
        return iter(sorted(self._docs, key=lambda d: d["_id"]))


class _FakeCollection:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    def replace_one(self, filter_, doc, upsert=False):
        self.docs[filter_["_id"]] = doc

    def find_one(self, filter_):
        return self.docs.get(filter_["_id"])

    def delete_one(self, filter_):
        existed = filter_["_id"] in self.docs
        self.docs.pop(filter_["_id"], None)
        result = MagicMock()
        result.deleted_count = 1 if existed else 0
        return result

    def find(self, filter_):
        return _FakeCursor(list(self.docs.values()))


@pytest.fixture
def fake_collection():
    collection = _FakeCollection()
    with patch("security_toolkit.scope_db._collection", return_value=collection):
        yield collection


def test_save_and_load_target_roundtrip(fake_collection):
    save_target({"name": "atum", "type": "wordpress", "base_url": "https://atum.xyz/"})
    result = load_target("atum")
    assert result == {"name": "atum", "type": "wordpress", "base_url": "https://atum.xyz/"}


def test_load_target_returns_none_when_absent(fake_collection):
    assert load_target("nope") is None


def test_save_target_requires_name(fake_collection):
    with pytest.raises(ValueError):
        save_target({"base_url": "https://x.test"})


def test_save_target_overwrites_existing(fake_collection):
    save_target({"name": "atum", "base_url": "https://old.test"})
    save_target({"name": "atum", "base_url": "https://new.test"})
    assert load_target("atum")["base_url"] == "https://new.test"


def test_delete_target_removes_and_reports_true(fake_collection):
    save_target({"name": "atum", "base_url": "https://atum.xyz/"})
    assert delete_target("atum") is True
    assert load_target("atum") is None


def test_delete_target_is_noop_and_reports_false_when_absent(fake_collection):
    assert delete_target("nonexistent") is False


def test_list_all_targets_sorted_by_name(fake_collection):
    save_target({"name": "b-target", "base_url": "https://b.test"})
    save_target({"name": "a-target", "base_url": "https://a.test"})
    names = [t["name"] for t in list_all_targets()]
    assert names == ["a-target", "b-target"]


def test_list_all_targets_empty_when_nothing_stored(fake_collection):
    assert list_all_targets() == ()


def test_stored_target_never_leaks_the_mongo_id_field(fake_collection):
    save_target({"name": "atum", "base_url": "https://atum.xyz/"})
    assert "_id" not in load_target("atum")
    assert all("_id" not in t for t in list_all_targets())
