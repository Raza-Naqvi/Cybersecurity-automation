"""Phase 4.2 (security-playbook.md) malware/phishing blacklist check —
black-box only.

Wraps Google's Safe Browsing Lookup API v4 (`threatMatches:find`) rather
than scraping a third-party scanner's web UI: same "is this URL flagged
as malicious by a reputable source" signal a tool like Sucuri SiteCheck
gives, but via an officially documented, free-tier, stable JSON API
instead of an undocumented endpoint with unclear terms.

This is the one HTTP request in this toolkit that does NOT go through
`scope_guard` — it never requests the target's own `base_url` at all,
only asks Google's API *about* it. The URL checked is always the
target's own `base_url`, never a free-form string a caller could point
elsewhere.

Needs a free API key (Google Cloud Console -> enable the "Safe Browsing
API" -> create a key) in `.env` as `GOOGLE_SAFE_BROWSING_API_KEY`.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from security_toolkit.config import Target

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")


@dataclass(frozen=True)
class SafeBrowsingResult:
    succeeded: bool
    flagged: bool
    threat_types: tuple[str, ...]
    detail: str


def check_safe_browsing(
    target: Target, api_key: str | None = None, timeout: float = 10.0
) -> SafeBrowsingResult:
    """Ask Google Safe Browsing whether the target's own base_url is a
    known malware/phishing/unwanted-software URL.

    A missing API key, a non-2xx response, or a network error are all
    flagged — never silently read as "no threats found", since that
    would hide "this check didn't actually run" behind a false all-clear
    (the same `dir_enum.py`/`run_nuclei` lesson applied here from the
    start).
    """
    if not target.base_url:
        raise RuntimeError(f"Target '{target.name}' has no base_url in scope.json")

    if not api_key:
        return SafeBrowsingResult(
            succeeded=False, flagged=True, threat_types=(),
            detail="GOOGLE_SAFE_BROWSING_API_KEY not set in .env — get a free key from the "
            "Google Cloud Console (enable the 'Safe Browsing API'), or skip this check.",
        )

    payload = {
        "client": {"clientId": "security-toolkit", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target.base_url}],
        },
    }

    try:
        response = requests.post(API_URL, params={"key": api_key}, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return SafeBrowsingResult(
            succeeded=False, flagged=True, threat_types=(), detail=f"Request to Safe Browsing API failed: {exc}"
        )

    if response.status_code != 200:
        return SafeBrowsingResult(
            succeeded=False, flagged=True, threat_types=(),
            detail=f"Safe Browsing API returned status {response.status_code}: {response.text[:500]}",
        )

    matches = response.json().get("matches") or []
    threat_types = tuple(dict.fromkeys(match.get("threatType", "UNKNOWN") for match in matches))
    flagged = len(threat_types) > 0
    detail = (
        f"FLAGGED by Google Safe Browsing: {', '.join(threat_types)}"
        if flagged
        else "No threats found by Google Safe Browsing."
    )
    return SafeBrowsingResult(succeeded=True, flagged=flagged, threat_types=threat_types, detail=detail)
