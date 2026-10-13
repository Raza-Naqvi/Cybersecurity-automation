"""Index of every report ever generated (any target, any machine), kept
in MongoDB alongside the credential store. Not the reports themselves —
just where to find them (Cloudinary URLs) plus enough metadata to list
and filter without re-reading the files. This is what the planned
dashboard will query.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from security_toolkit.config import get_mongo_database

COLLECTION_NAME = "report_index"


@dataclass(frozen=True)
class ReportIndexEntry:
    id: str
    target_name: str
    title: str
    generated_at: str
    json_url: str
    html_url: str
    flagged: bool
    # The full findings list (name/flagged/detail dicts), stored here too so
    # scripts/generate_findings_report.py can build a consolidated write-up
    # without re-fetching every report from Cloudinary. Empty for older
    # entries written before this field existed.
    findings: tuple[dict, ...] = ()


def _collection(uri: str | None = None, db_name: str | None = None) -> Any:
    return get_mongo_database(uri, db_name)[COLLECTION_NAME]


def add_report_entry(
    target_name: str,
    title: str,
    generated_at: str,
    json_url: str,
    html_url: str,
    flagged: bool,
    findings: tuple[dict, ...] = (),
    uri: str | None = None,
) -> ReportIndexEntry:
    entry_id = str(uuid.uuid4())
    collection = _collection(uri)
    collection.insert_one(
        {
            "_id": entry_id,
            "target_name": target_name,
            "title": title,
            "generated_at": generated_at,
            "json_url": json_url,
            "html_url": html_url,
            "flagged": flagged,
            "findings": list(findings),
            "indexed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return ReportIndexEntry(
        id=entry_id,
        target_name=target_name,
        title=title,
        generated_at=generated_at,
        json_url=json_url,
        html_url=html_url,
        flagged=flagged,
        findings=findings,
    )


def list_report_entries(target_name: str | None = None, uri: str | None = None) -> tuple[ReportIndexEntry, ...]:
    collection = _collection(uri)
    query = {} if target_name is None else {"target_name": target_name}
    docs = collection.find(query).sort([("generated_at", -1)])
    return tuple(
        ReportIndexEntry(
            id=doc["_id"],
            target_name=doc["target_name"],
            title=doc["title"],
            generated_at=doc["generated_at"],
            json_url=doc["json_url"],
            html_url=doc["html_url"],
            flagged=doc["flagged"],
            findings=tuple(doc.get("findings", ())),
        )
        for doc in docs
    )
