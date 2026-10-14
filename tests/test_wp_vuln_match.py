from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from security_toolkit.recon.wp_enum import SoftwareFinding, WpEnumResult
from security_toolkit.recon.wp_vuln_match import (
    _version_in_range,
    fetch_vulnerability_feed,
    get_vulnerability_feed,
    match_vulnerabilities,
    run_wp_vuln_match,
)


class FakeCollection:
    """Minimal find_one/find/delete_many/insert_many/replace_one stand-in
    — just enough of pymongo's Collection API to test the sharded cache
    without a real MongoDB.
    """

    def __init__(self):
        self._docs: dict = {}

    def find_one(self, query):
        return self._docs.get(query["_id"])

    def find(self, query):
        feed = query.get("feed")
        return [doc for doc in self._docs.values() if doc.get("feed") == feed and "_meta" not in doc]

    def delete_many(self, query):
        feed = query.get("feed")
        for doc_id in [doc_id for doc_id, doc in self._docs.items() if doc.get("feed") == feed and "_meta" not in doc]:
            del self._docs[doc_id]

    def insert_many(self, docs):
        for doc in docs:
            self._docs[doc["_id"]] = doc

    def replace_one(self, query, doc, upsert=False):
        self._docs[query["_id"]] = doc


SAMPLE_FEED = {
    "uuid-1": {
        "id": "uuid-1",
        "title": "Example Plugin < 1.2.3 - XSS",
        "software": [
            {
                "type": "plugin",
                "name": "Example Plugin",
                "slug": "example",
                "affected_versions": {
                    "1.0.0 - 1.2.3": {
                        "from_version": "1.0.0",
                        "from_inclusive": True,
                        "to_version": "1.2.3",
                        "to_inclusive": True,
                    }
                },
                "patched": True,
                "patched_versions": ["1.2.4"],
            }
        ],
        "informational": False,
        "cve": "CVE-1998-1000",
        "cvss": {"score": 6.5, "rating": "Medium"},
        "copyrights": {"mitre": {"notice": "Copyright 1999-2022 The MITRE Corporation"}},
    }
}


def test_fetch_vulnerability_feed_requires_api_key():
    with pytest.raises(RuntimeError):
        fetch_vulnerability_feed(None)


def test_fetch_vulnerability_feed_sends_bearer_header_and_parses_json():
    response = MagicMock(status_code=200)
    response.json.return_value = SAMPLE_FEED
    with patch("requests.get", return_value=response) as mock_get:
        data = fetch_vulnerability_feed("my-key")
    assert data == SAMPLE_FEED
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer my-key"


def test_fetch_vulnerability_feed_raises_on_429():
    with patch("requests.get", return_value=MagicMock(status_code=429, text="")):
        with pytest.raises(RuntimeError, match="rate limit"):
            fetch_vulnerability_feed("my-key")


def test_fetch_vulnerability_feed_raises_on_non_200():
    with patch("requests.get", return_value=MagicMock(status_code=500, text="boom")):
        with pytest.raises(RuntimeError):
            fetch_vulnerability_feed("my-key")


def _seed_cache(collection: FakeCollection, feed: str, fetched_at: datetime, data: dict) -> None:
    """Populate a FakeCollection the same sharded way get_vulnerability_feed writes it."""
    collection.insert_many(
        [{"_id": f"{feed}:{vuln_id}", "feed": feed, "vuln_id": vuln_id, "record": record} for vuln_id, record in data.items()]
    )
    collection.replace_one({"_id": f"{feed}:_meta"}, {"_id": f"{feed}:_meta", "feed": feed, "_meta": True, "fetched_at": fetched_at})


def test_get_vulnerability_feed_uses_cache_when_fresh():
    collection = FakeCollection()
    _seed_cache(collection, "production", datetime.now(timezone.utc), SAMPLE_FEED)
    with patch("requests.get") as mock_get:
        data = get_vulnerability_feed("my-key", cache_collection=collection)
    assert data == SAMPLE_FEED
    mock_get.assert_not_called()


def test_get_vulnerability_feed_refetches_when_stale():
    collection = FakeCollection()
    stale_time = datetime.now(timezone.utc) - timedelta(hours=48)
    _seed_cache(collection, "production", stale_time, {"old-uuid": {"id": "old-uuid", "software": []}})
    response = MagicMock(status_code=200)
    response.json.return_value = SAMPLE_FEED
    with patch("requests.get", return_value=response) as mock_get:
        data = get_vulnerability_feed("my-key", cache_collection=collection)
    assert data == SAMPLE_FEED
    mock_get.assert_called_once()
    # the stale record is gone, replaced by the freshly fetched ones
    assert [doc for doc in collection.find({"feed": "production"}) if doc["vuln_id"] == "old-uuid"] == []


def test_get_vulnerability_feed_treats_naive_cached_datetime_as_utc():
    """Real pymongo round-trips datetimes as naive UTC — the cache check
    must not crash comparing aware "now" against a naive stored value.
    """
    collection = FakeCollection()
    fresh_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    _seed_cache(collection, "production", fresh_naive, SAMPLE_FEED)
    with patch("requests.get") as mock_get:
        data = get_vulnerability_feed("my-key", cache_collection=collection)
    assert data == SAMPLE_FEED
    mock_get.assert_not_called()


def test_get_vulnerability_feed_fetches_and_caches_when_no_cache():
    collection = FakeCollection()
    response = MagicMock(status_code=200)
    response.json.return_value = SAMPLE_FEED
    with patch("requests.get", return_value=response) as mock_get:
        data = get_vulnerability_feed("my-key", cache_collection=collection)
    assert data == SAMPLE_FEED
    mock_get.assert_called_once()
    cached = {doc["vuln_id"]: doc["record"] for doc in collection.find({"feed": "production"})}
    assert cached == SAMPLE_FEED


def test_get_vulnerability_feed_shards_large_feeds_across_many_documents():
    """The real bug this guards against: Wordfence's feed is thousands of
    records — storing it as one document's field blows past MongoDB's
    16MB single-document limit. Each record must be its own document.
    """
    collection = FakeCollection()
    big_feed = {f"uuid-{i}": {"id": f"uuid-{i}", "software": []} for i in range(500)}
    response = MagicMock(status_code=200)
    response.json.return_value = big_feed
    with patch("requests.get", return_value=response):
        data = get_vulnerability_feed("my-key", cache_collection=collection)
    assert data == big_feed
    # 500 record documents + 1 metadata document, never one giant blob
    assert len([d for d in collection._docs.values() if "_meta" not in d]) == 500
    assert collection.find_one({"_id": "production:_meta"}) is not None


def test_version_in_range_inclusive_bounds():
    range_info = {"from_version": "1.0.0", "from_inclusive": True, "to_version": "1.2.3", "to_inclusive": True}
    assert _version_in_range("1.0.0", range_info) is True
    assert _version_in_range("1.2.3", range_info) is True
    assert _version_in_range("1.2.4", range_info) is False
    assert _version_in_range("0.9.9", range_info) is False


def test_version_in_range_exclusive_bounds():
    range_info = {"from_version": "1.0.0", "from_inclusive": False, "to_version": "1.2.3", "to_inclusive": False}
    assert _version_in_range("1.0.0", range_info) is False
    assert _version_in_range("1.2.3", range_info) is False
    assert _version_in_range("1.0.1", range_info) is True


def test_version_in_range_wildcard_from():
    range_info = {"from_version": "*", "from_inclusive": True, "to_version": "1.0.0", "to_inclusive": True}
    assert _version_in_range("0.0.1", range_info) is True
    assert _version_in_range("1.0.1", range_info) is False


def test_version_in_range_wildcard_to():
    range_info = {"from_version": "1.0.0", "from_inclusive": True, "to_version": "*", "to_inclusive": True}
    assert _version_in_range("99.0.0", range_info) is True
    assert _version_in_range("0.0.1", range_info) is False


def test_version_in_range_handles_different_length_versions():
    range_info = {"from_version": "1.2", "from_inclusive": True, "to_version": "1.2", "to_inclusive": True}
    assert _version_in_range("1.2.0", range_info) is True


def test_match_vulnerabilities_flags_version_in_range():
    findings = (SoftwareFinding(slug="example", version="1.2.0", source="passive"),)
    matches = match_vulnerabilities(findings, "plugin", SAMPLE_FEED)
    assert len(matches) == 1
    assert matches[0].cve == "CVE-1998-1000"
    assert matches[0].severity == "Medium"
    assert matches[0].patched_versions == ("1.2.4",)
    assert matches[0].mitre_notice is not None


def test_match_vulnerabilities_does_not_flag_patched_version():
    findings = (SoftwareFinding(slug="example", version="2.0.0", source="passive"),)
    assert match_vulnerabilities(findings, "plugin", SAMPLE_FEED) == ()


def test_match_vulnerabilities_ignores_other_software_types():
    findings = (SoftwareFinding(slug="example", version="1.2.0", source="passive"),)
    assert match_vulnerabilities(findings, "theme", SAMPLE_FEED) == ()


def test_match_vulnerabilities_skips_unknown_version():
    findings = (SoftwareFinding(slug="example", version=None, source="passive"),)
    assert match_vulnerabilities(findings, "plugin", SAMPLE_FEED) == ()


def test_run_wp_vuln_match_returns_empty_for_non_wordpress():
    result = WpEnumResult(
        is_wordpress=False, core_version=None, plugins=(), themes=(), usernames=(), rate_limit=None, detail=""
    )
    outcome = run_wp_vuln_match(result, api_key="key")
    assert outcome.succeeded is True
    assert outcome.flagged is False
    assert outcome.matches == ()


def test_run_wp_vuln_match_reports_failure_without_crashing_when_key_missing():
    result = WpEnumResult(
        is_wordpress=True,
        core_version=None,
        plugins=(SoftwareFinding(slug="example", version="1.2.0", source="passive"),),
        themes=(),
        usernames=(),
        rate_limit=None,
        detail="",
    )
    outcome = run_wp_vuln_match(result, api_key=None, cache_collection=FakeCollection())
    assert outcome.succeeded is False
    assert outcome.flagged is True


def test_run_wp_vuln_match_reports_failure_on_rate_limit():
    result = WpEnumResult(
        is_wordpress=True,
        core_version=None,
        plugins=(SoftwareFinding(slug="example", version="1.2.0", source="passive"),),
        themes=(),
        usernames=(),
        rate_limit=None,
        detail="",
    )
    with patch("requests.get", return_value=MagicMock(status_code=429, text="")):
        outcome = run_wp_vuln_match(result, api_key="key", cache_collection=FakeCollection())
    assert outcome.succeeded is False
    assert outcome.flagged is True
    assert "rate limit" in outcome.detail.lower()


def test_run_wp_vuln_match_full_flow_plugin_and_core():
    result = WpEnumResult(
        is_wordpress=True,
        core_version="1.2.0",
        plugins=(SoftwareFinding(slug="example", version="1.2.0", source="passive"),),
        themes=(),
        usernames=(),
        rate_limit=None,
        detail="",
    )
    response = MagicMock(status_code=200)
    response.json.return_value = SAMPLE_FEED
    with patch("requests.get", return_value=response):
        outcome = run_wp_vuln_match(result, api_key="key", cache_collection=FakeCollection())
    assert outcome.succeeded is True
    assert outcome.flagged is True
    assert len(outcome.matches) == 1
    assert outcome.matches[0].cve == "CVE-1998-1000"
    assert outcome.matches[0].slug == "example"


def test_run_wp_vuln_match_not_flagged_when_nothing_matches():
    result = WpEnumResult(
        is_wordpress=True,
        core_version=None,
        plugins=(SoftwareFinding(slug="safe-plugin", version="9.9.9", source="passive"),),
        themes=(),
        usernames=(),
        rate_limit=None,
        detail="",
    )
    response = MagicMock(status_code=200)
    response.json.return_value = SAMPLE_FEED
    with patch("requests.get", return_value=response):
        outcome = run_wp_vuln_match(result, api_key="key", cache_collection=FakeCollection())
    assert outcome.succeeded is True
    assert outcome.flagged is False
    assert outcome.matches == ()
