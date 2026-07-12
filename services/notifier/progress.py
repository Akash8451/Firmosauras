"""Per-job progress derivation from the `firmware.*` event stream.

Turns the raw pipeline events into a compact progress snapshot the frontend can
render ("14/40 sub-blobs matched"). The matched/total counts prefer the Redis
counters (`matched_children` / `total_children`, SCHEMA.md §3) when a Redis client
is available — those are the authoritative fan-out counters — and otherwise fall
back to counting events seen. Pure and synchronous, so it's trivially testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from shared import topics
from shared.redis_keys import matched_children, total_children

_STAGE_BY_TOPIC = {
    topics.FIRMWARE_UPLOADED: "uploaded",
    topics.FIRMWARE_TRIAGED: "triaged",
    topics.FIRMWARE_EXTRACTED: "extracted",
    topics.FIRMWARE_ANALYZED: "analyzed",
    topics.FIRMWARE_MATCHED: "matched",
    topics.FIRMWARE_COMPLETED: "completed",
    topics.FIRMWARE_DLQ: "error",
}


@dataclass
class _JobState:
    extracted: int = 0
    analyzed: int = 0
    matched: int = 0
    total_events: int = 0
    status: str = "in_progress"
    last_stage: str = "uploaded"


@dataclass
class ProgressTracker:
    """Accumulates per-job counts and emits progress snapshots."""

    redis: object = None
    _jobs: Dict[str, _JobState] = field(default_factory=dict)

    def _state(self, job_id: str) -> _JobState:
        st = self._jobs.get(job_id)
        if st is None:
            st = _JobState()
            self._jobs[job_id] = st
        return st

    def _redis_int(self, key: str) -> Optional[int]:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(key)
            return int(raw) if raw is not None else None
        except Exception:
            return None

    def update(self, topic: str, payload: dict) -> Optional[dict]:
        """Fold one event into the job's state; return the new snapshot (or None
        for an event without a resolvable job_id, e.g. some DLQ records)."""
        job_id = payload.get("job_id")
        if not job_id:
            return None

        st = self._state(job_id)
        st.total_events += 1
        st.last_stage = _STAGE_BY_TOPIC.get(topic, topic)

        if topic == topics.FIRMWARE_EXTRACTED:
            st.extracted += 1
        elif topic == topics.FIRMWARE_ANALYZED:
            st.analyzed += 1
        elif topic == topics.FIRMWARE_MATCHED:
            st.matched += 1
        elif topic == topics.FIRMWARE_COMPLETED:
            st.status = "complete"
        elif topic == topics.FIRMWARE_DLQ:
            st.status = "error"

        return self.snapshot(job_id)

    def snapshot(self, job_id: str) -> dict:
        st = self._state(job_id)

        # Authoritative counters from Redis when present, else event-derived.
        matched = self._redis_int(matched_children(job_id))
        if matched is None:
            matched = st.matched
        total = self._redis_int(total_children(job_id))
        total_final = total is not None
        if total is None:
            total = st.extracted  # provisional running total from fan-out events

        percent = round((matched / total) * 100.0, 1) if total else 0.0
        return {
            "job_id": job_id,
            "stage": st.last_stage,
            "status": st.status,
            "matched": matched,
            "total": total,
            "total_final": total_final,
            "progress": f"{matched}/{total}",
            "percent": percent,
            "counts": {
                "extracted": st.extracted,
                "analyzed": st.analyzed,
                "matched": st.matched,
            },
        }
