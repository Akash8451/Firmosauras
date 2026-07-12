"""Task 12 — per-job progress derivation (X/N matched)."""
from __future__ import annotations

from shared import topics
from shared.redis_keys import matched_children, total_children

from services.notifier.progress import ProgressTracker


class _MiniRedis:
    def __init__(self):
        self._d = {}

    def set(self, k, v):
        self._d[k] = str(v)

    def get(self, k):
        return self._d.get(k)


def _extracted(job, sub):
    return {"job_id": job, "sub_blob_id": sub, "s3_key": f"extracted/{job}/{sub}.bin", "parent_blob_id": None}


def _matched(job, sub):
    return {"job_id": job, "sub_blob_id": sub, "cve_matches": []}


def test_progress_derived_from_events_without_redis():
    tracker = ProgressTracker()
    tracker.update(topics.FIRMWARE_EXTRACTED, _extracted("j", "b1"))
    tracker.update(topics.FIRMWARE_EXTRACTED, _extracted("j", "b2"))
    snap = tracker.update(topics.FIRMWARE_MATCHED, _matched("j", "b1"))

    assert snap["job_id"] == "j"
    assert snap["matched"] == 1
    assert snap["total"] == 2          # provisional total from extracted events
    assert snap["progress"] == "1/2"
    assert snap["percent"] == 50.0
    assert snap["total_final"] is False
    assert snap["stage"] == "matched"


def test_progress_prefers_redis_counters():
    redis = _MiniRedis()
    redis.set(total_children("j"), 40)
    redis.set(matched_children("j"), 14)
    tracker = ProgressTracker(redis=redis)

    snap = tracker.update(topics.FIRMWARE_MATCHED, _matched("j", "b1"))
    assert snap["matched"] == 14
    assert snap["total"] == 40
    assert snap["total_final"] is True
    assert snap["progress"] == "14/40"
    assert snap["percent"] == 35.0


def test_progress_status_transitions():
    tracker = ProgressTracker()
    tracker.update(topics.FIRMWARE_UPLOADED, {"job_id": "j", "s3_key": "k", "uploaded_by": "u", "uploaded_at": "2026-07-12T00:00:00Z"})
    done = tracker.update(topics.FIRMWARE_COMPLETED, {"job_id": "j", "status": "COMPLETE", "report_s3_key": "r", "sbom_s3_key": "s"})
    assert done["status"] == "complete"

    err = tracker.update(topics.FIRMWARE_DLQ, {"original_topic": "firmware.analyzed", "payload": '{"job_id": "j"}', "error": "x", "failed_at": "2026-07-12T00:00:00Z"})
    # DLQ record without a top-level job_id yields no snapshot; here we passed none.
    assert err is None or err["status"] == "error"


def test_dlq_without_job_id_returns_none():
    tracker = ProgressTracker()
    snap = tracker.update(topics.FIRMWARE_DLQ, {"original_topic": "x", "payload": "{}", "error": "e", "failed_at": "2026-07-12T00:00:00Z"})
    assert snap is None
