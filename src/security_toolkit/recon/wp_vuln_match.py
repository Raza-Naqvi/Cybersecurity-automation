"""Phase 4.2/4.4 (security-playbook.md) WordPress vulnerability matching
— the second half of our WPScan alternative (see wp_enum.py for the
enumeration half).

Matches plugin/theme/core versions detected by `wp_enum.py` against
the free **Wordfence Intelligence** vulnerability feed (V3), instead
of WPScan's own capped (25 req/day), non-commercial-use-only API.

This is a request *about* detected software, not the target itself —
same category as `safe_browsing_check.py` — so it deliberately does
NOT go through `security_toolkit.scope_guard`.

Wordfence's V3 feed requires a free API key (`Authorization: Bearer`)
and enforces usage limits with a plain HTTP 429 rather than a fixed
published number, so the full feed (one JSON blob, no filter
parameters) is fetched at most once per `CACHE_MAX_AGE` and cached in
this toolkit's own MongoDB store — never local disk, never the
target's own data — and reused across runs rather than re-fetched
every time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from security_toolkit.config import get_mongo_database
from security_toolkit.recon.wp_enum import SoftwareFinding, WpEnumResult

API_HOST = "https://www.wordfence.com"
FEED_PATHS = {
    "production": "/api/intelligence/v3/vulnerabilities/production",
    "scanner": "/api/intelligence/v3/vulnerabilities/scanner",
}
CACHE_COLLECTION_NAME = "wordfence_vuln_feed_cache"
CACHE_MAX_AGE = timedelta(hours=24)

_VERSION_PART_RE = re.compile(r"\d+")


@dataclass(frozen=True)
class VulnMatch:
    slug: str
    detected_version: str
    software_type: str  # "core", "plugin", or "theme"
    title: str
    cve: str | None
    severity: str | None  # CVSS rating: None/Low/Medium/High/Critical
    cvss_score: float | None
    informational: bool
    patched_versions: tuple[str, ...]
    mitre_notice: str | None  # required attribution when `cve` is set, per Wordfence's terms
    detail: str


@dataclass(frozen=True)
class VulnMatchResult:
    succeeded: bool
    flagged: bool
    matches: tuple[VulnMatch, ...]
    detail: str


def fetch_vulnerability_feed(api_key: str | None, feed: str = "production", timeout: float = 30.0) -> dict:
    """One GET against Wordfence's full vulnerability feed. Both feed
    endpoints return the complete database — no filter parameters — so
    callers should go through `get_vulnerability_feed` for caching
    rather than calling this directly on every check.
    """
    if not api_key:
        raise RuntimeError(
            "WORDFENCE_API_KEY not set — get a free key from your Wordfence.com account's "
            "Integrations page, or skip vulnerability matching."
        )
    url = f"{API_HOST}{FEED_PATHS[feed]}"
    response = requests.get(url, headers={"Authorization": f"Bearer {api_key}"}, timeout=timeout)
    if response.status_code == 429:
        raise RuntimeError(
            "Wordfence Intelligence API rate limit hit (HTTP 429) — back off and retry later, "
            "or request a higher limit from wfi-support@wordfence.com."
        )
    if response.status_code != 200:
        raise RuntimeError(f"Wordfence Intelligence API returned status {response.status_code}: {response.text[:300]}")
    return response.json()


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def get_vulnerability_feed(
    api_key: str | None,
    feed: str = "production",
    max_age: timedelta = CACHE_MAX_AGE,
    timeout: float = 30.0,
    cache_collection: Any = None,
) -> dict:
    """`fetch_vulnerability_feed`, cached in MongoDB for `max_age` —
    Wordfence's own full-feed-only, rate-limited API means re-fetching
    on every scan run would burn through the limit fast.
    """
    collection = cache_collection if cache_collection is not None else get_mongo_database()[CACHE_COLLECTION_NAME]
    cached = collection.find_one({"_id": feed})
    now = datetime.now(timezone.utc)
    if cached and (now - _as_utc(cached["fetched_at"])) < max_age:
        return cached["data"]

    data = fetch_vulnerability_feed(api_key, feed=feed, timeout=timeout)
    collection.replace_one({"_id": feed}, {"_id": feed, "fetched_at": now, "data": data}, upsert=True)
    return data


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in _VERSION_PART_RE.findall(version)) or (0,)


def _compare_versions(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _version_in_range(version: str, range_info: dict) -> bool:
    from_version = range_info.get("from_version", "*")
    to_version = range_info.get("to_version", "*")

    if from_version != "*":
        cmp = _compare_versions(version, from_version)
        if cmp < 0 or (cmp == 0 and not range_info.get("from_inclusive", True)):
            return False
    if to_version != "*":
        cmp = _compare_versions(version, to_version)
        if cmp > 0 or (cmp == 0 and not range_info.get("to_inclusive", True)):
            return False
    return True


def match_vulnerabilities(
    findings: tuple[SoftwareFinding, ...], software_type: str, feed_data: dict
) -> tuple[VulnMatch, ...]:
    """Match detected `(slug, version)` pairs against every record in
    the feed — a signal for manual confirmation, not a final verdict,
    same discipline as every other scanner wrapper in this toolkit. A
    finding with no detected version is skipped (nothing to compare),
    not flagged — `wp_enum.py`'s own result already surfaces "version
    unknown" separately.
    """
    matches = []
    for finding in findings:
        if not finding.version:
            continue
        for record in feed_data.values():
            for software in record.get("software", []):
                if software.get("type") != software_type or software.get("slug") != finding.slug:
                    continue
                for range_info in software.get("affected_versions", {}).values():
                    if not _version_in_range(finding.version, range_info):
                        continue
                    cvss = record.get("cvss") or {}
                    cve = record.get("cve")
                    mitre_notice = (record.get("copyrights") or {}).get("mitre", {}).get("notice") if cve else None
                    patched_versions = tuple(software.get("patched_versions", []))
                    matches.append(
                        VulnMatch(
                            slug=finding.slug,
                            detected_version=finding.version,
                            software_type=software_type,
                            title=record.get("title", ""),
                            cve=cve,
                            severity=cvss.get("rating"),
                            cvss_score=cvss.get("score"),
                            informational=bool(record.get("informational", False)),
                            patched_versions=patched_versions,
                            mitre_notice=mitre_notice,
                            detail=(
                                f"{finding.slug} {finding.version}: {record.get('title', '')} "
                                f"({cve or 'no CVE assigned'}) — "
                                + (
                                    f"patched in {', '.join(patched_versions)}"
                                    if patched_versions
                                    else "no patched version listed"
                                )
                            ),
                        )
                    )
    return tuple(matches)


def run_wp_vuln_match(
    wp_enum_result: WpEnumResult,
    api_key: str | None,
    feed: str = "production",
    timeout: float = 30.0,
    cache_collection: Any = None,
) -> VulnMatchResult:
    """Orchestrates matching for every software type `wp_enum.py` found.
    A missing key, rate limit, or any other feed failure never crashes
    the run — it's reported as `succeeded=False, flagged=True`, same
    "never silently succeed when the call actually failed" rule as
    `safe_browsing_check.py`.
    """
    if not wp_enum_result.is_wordpress:
        return VulnMatchResult(succeeded=True, flagged=False, matches=(), detail="Not a WordPress target — nothing to match.")

    try:
        feed_data = get_vulnerability_feed(api_key, feed=feed, timeout=timeout, cache_collection=cache_collection)
    except RuntimeError as exc:
        return VulnMatchResult(succeeded=False, flagged=True, matches=(), detail=f"Could not check vulnerabilities: {exc}")

    plugin_matches = match_vulnerabilities(wp_enum_result.plugins, "plugin", feed_data)
    theme_matches = match_vulnerabilities(wp_enum_result.themes, "theme", feed_data)
    core_matches = ()
    if wp_enum_result.core_version:
        core_finding = (SoftwareFinding(slug="wordpress", version=wp_enum_result.core_version, source="active"),)
        core_matches = match_vulnerabilities(core_finding, "core", feed_data)

    matches = plugin_matches + theme_matches + core_matches
    detail = (
        f"{len(matches)} known vulnerability match(es) found."
        if matches
        else "No known vulnerabilities matched for the detected versions."
    )
    return VulnMatchResult(succeeded=True, flagged=len(matches) > 0, matches=matches, detail=detail)
