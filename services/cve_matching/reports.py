"""Report store — MongoDB `reports` collection (SCHEMA.md §7) + in-memory fake.

One document per `job_id`. As `firmware.matched` events arrive the aggregator
records each sub-blob's matches (a PARTIAL doc); once the completion gate passes
it transitions the doc to COMPLETE with the assembled report.

Two invariants matter for replay-safety (Task 11):
  * `record_sub_blob` is an idempotent UPSERT keyed on `job_id` that sets the
    entry for a SPECIFIC sub-blob — re-delivering the same `firmware.matched`
    overwrites that sub-blob's slot, it never appends. So a job always has
    exactly one document and each sub-blob exactly one entry.
  * `finalize` is an ATOMIC transition (`status != COMPLETE` -> COMPLETE). Only
    the caller that performs the transition gets `True`; a replay (or a second
    sub-blob racing the gate) gets `False` and must NOT re-emit `firmware.completed`.
"""
from __future__ import annotations

import copy
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Protocol

log = logging.getLogger("cve_matching.reports")

STATUS_PARTIAL = "PARTIAL"
STATUS_COMPLETE = "COMPLETE"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReportStore(Protocol):
    def record_sub_blob(self, job_id: str, sub_blob_id: str, cve_matches: List[dict]) -> None: ...

    def get(self, job_id: str) -> Optional[dict]: ...

    def finalize(self, job_id: str, report_fields: dict) -> bool: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests).                                                      #
# --------------------------------------------------------------------------- #
class InMemoryReportStore:
    def __init__(self) -> None:
        self._docs: Dict[str, dict] = {}

    def record_sub_blob(self, job_id: str, sub_blob_id: str, cve_matches: List[dict]) -> None:
        doc = self._docs.get(job_id)
        if doc is None:
            doc = {"job_id": job_id, "status": STATUS_PARTIAL, "sub_blobs": {}}
            self._docs[job_id] = doc
        # Overwrite this sub-blob's slot (idempotent; never appends).
        doc["sub_blobs"][sub_blob_id] = copy.deepcopy(cve_matches)
        doc["updated_at"] = _now_iso()

    def get(self, job_id: str) -> Optional[dict]:
        doc = self._docs.get(job_id)
        return copy.deepcopy(doc) if doc is not None else None

    def finalize(self, job_id: str, report_fields: dict) -> bool:
        doc = self._docs.get(job_id)
        if doc is None:
            doc = {"job_id": job_id, "status": STATUS_PARTIAL, "sub_blobs": {}}
            self._docs[job_id] = doc
        if doc.get("status") == STATUS_COMPLETE:
            return False  # already finalized — replay / race loser
        doc.update(copy.deepcopy(report_fields))
        doc["status"] = STATUS_COMPLETE
        return True


# --------------------------------------------------------------------------- #
# MongoDB-backed store.                                                        #
# --------------------------------------------------------------------------- #
class MongoReportStore:
    def __init__(self, *, mongo_url: Optional[str] = None, db_name: Optional[str] = None) -> None:
        self.mongo_url = mongo_url or os.getenv("MONGO_URL", "mongodb://localhost:27017/firmosaurus")
        self.db_name = db_name or os.getenv("MONGO_DB", "firmosaurus")
        self._client = None
        self._collection = None

    def _coll(self):
        if self._collection is None:
            from pymongo import MongoClient  # lazy

            self._client = MongoClient(self.mongo_url)
            self._collection = self._client[self.db_name]["reports"]
            # Unique index on job_id guarantees one document per job.
            self._collection.create_index("job_id", unique=True)
        return self._collection

    def record_sub_blob(self, job_id: str, sub_blob_id: str, cve_matches: List[dict]) -> None:
        self._coll().update_one(
            {"job_id": job_id},
            {
                "$set": {
                    f"sub_blobs.{sub_blob_id}": cve_matches,
                    "updated_at": _now_iso(),
                },
                "$setOnInsert": {"job_id": job_id, "status": STATUS_PARTIAL},
            },
            upsert=True,
        )

    def get(self, job_id: str) -> Optional[dict]:
        return self._coll().find_one({"job_id": job_id}, {"_id": False})

    def finalize(self, job_id: str, report_fields: dict) -> bool:
        fields = dict(report_fields)
        fields["status"] = STATUS_COMPLETE
        # Atomic guard: only transition when not already COMPLETE. `upsert=True`
        # covers the (unlikely) case that no partial exists yet.
        result = self._coll().update_one(
            {"job_id": job_id, "status": {"$ne": STATUS_COMPLETE}},
            {"$set": fields, "$setOnInsert": {"job_id": job_id}},
            upsert=True,
        )
        # A real transition either modified the existing doc or inserted a new one.
        return bool(result.modified_count == 1 or result.upserted_id is not None)
