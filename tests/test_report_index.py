from unittest.mock import patch

import pytest

from security_toolkit.report_index import add_report_entry, list_report_entries


class _FakeCursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, _keys):
        return iter(sorted(self._docs, key=lambda d: d["generated_at"], reverse=True))


class _FakeCollection:
    def __init__(self):
        self.docs = {}

    def insert_one(self, doc):
        self.docs[doc["_id"]] = doc

    def find(self, filter_):
        if not filter_:
            matched = list(self.docs.values())
        else:
            matched = [d for d in self.docs.values() if d.get("target_name") == filter_.get("target_name")]
        return _FakeCursor(matched)


@pytest.fixture
def fake_collection():
    collection = _FakeCollection()
    with patch("security_toolkit.report_index._collection", return_value=collection):
        yield collection


def test_add_report_entry_stores_all_fields(fake_collection):
    entry = add_report_entry(
        target_name="cheerlytics",
        title="Recon",
        generated_at="2026-01-01T00:00:00+00:00",
        json_url="https://cdn.test/a.json",
        html_url="https://cdn.test/a.html",
        flagged=True,
    )
    assert entry.target_name == "cheerlytics"
    assert entry.flagged is True
    assert len(fake_collection.docs) == 1


def test_add_report_entry_stores_findings(fake_collection):
    findings = ({"name": "check 1", "flagged": True, "detail": "bad"},)
    add_report_entry(
        target_name="cheerlytics",
        title="Recon",
        generated_at="2026-01-01T00:00:00+00:00",
        json_url="u1",
        html_url="u2",
        flagged=True,
        findings=findings,
    )
    result = list_report_entries("cheerlytics")[0]
    assert result.findings == findings


def test_list_report_entries_defaults_findings_to_empty_for_old_docs(fake_collection):
    # simulate an entry written before the `findings` field existed
    fake_collection.docs["legacy-id"] = {
        "_id": "legacy-id", "target_name": "site-c", "title": "Recon",
        "generated_at": "2026-01-01T00:00:00+00:00", "json_url": "u1", "html_url": "u2", "flagged": False,
    }
    result = list_report_entries("site-c")[0]
    assert result.findings == ()


def test_list_report_entries_filters_by_target(fake_collection):
    add_report_entry("site-a", "Recon", "2026-01-01T00:00:00+00:00", "u1", "u2", False)
    add_report_entry("site-b", "Recon", "2026-01-02T00:00:00+00:00", "u3", "u4", True)

    results = list_report_entries("site-a")

    assert len(results) == 1
    assert results[0].target_name == "site-a"


def test_list_report_entries_without_target_returns_all_sorted_newest_first(fake_collection):
    add_report_entry("site-a", "Recon", "2026-01-01T00:00:00+00:00", "u1", "u2", False)
    add_report_entry("site-b", "Recon", "2026-01-02T00:00:00+00:00", "u3", "u4", True)

    results = list_report_entries()

    assert len(results) == 2
    assert results[0].generated_at == "2026-01-02T00:00:00+00:00"
