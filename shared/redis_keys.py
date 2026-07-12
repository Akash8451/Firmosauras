"""Redis key builders — SCHEMA.md §3.

Every handler MUST build keys through these functions rather than formatting
strings inline, so the exact patterns (`job:{job_id}:total_children`, etc.) stay
consistent across sessions and groups. Variant spellings (`children_total`,
`child_count`, ...) are forbidden.

All keys live on a single `noeviction` Redis instance (all state here is
structural: counters, markers, locks, idempotency flags — no cache tier).
"""
from __future__ import annotations

# Single hand-rolled Bloom filter bitmap for firmware-hash dedup (SCHEMA.md §3).
# NOT RedisBloom / BF.* — a plain bitmap driven with SETBIT/GETBIT.
_BLOOM_KEY = "bloom:firmware_hashes"


def bloom_key() -> str:
    """Key for the dedup Bloom filter bitmap (`bloom:firmware_hashes`)."""
    return _BLOOM_KEY


def total_children(job_id: str) -> str:
    """Fan-out total-children counter (`job:{job_id}:total_children`).

    Incremented by the unpacker as it discovers sub-blobs.
    """
    return f"job:{job_id}:total_children"


def completed_children(job_id: str) -> str:
    """Analysis-stage counter (`job:{job_id}:completed_children`).

    Incremented at `firmware.analyzed`. NOTE: the aggregator does NOT gate on this
    — a child can be analyzed but not yet matched. Gating here fires early.
    """
    return f"job:{job_id}:completed_children"


def matched_children(job_id: str) -> str:
    """CVE-match-stage counter (`job:{job_id}:matched_children`).

    Incremented at `firmware.matched`. This is the counter the aggregator gates on
    (`matched_children == total_children` AND `extraction_complete`).
    """
    return f"job:{job_id}:matched_children"


def extraction_complete(job_id: str) -> str:
    """Extraction-complete marker (`job:{job_id}:extraction_complete`).

    Boolean flag (0/1) set by the unpacker once fan-out discovery is finished, so
    the aggregator never fires while new sub-blobs are still being discovered.
    """
    return f"job:{job_id}:extraction_complete"


def dlq_lock_key(job_id: str) -> str:
    """Redlock key for a DLQ retry claim (`lock:dlq_retry:{job_id}`), short TTL."""
    return f"lock:dlq_retry:{job_id}"


def idempotency_key(topic: str, message_key: str) -> str:
    """Processed-message idempotency flag (`processed:{topic}:{message_key}`).

    Check-and-set before processing so a re-delivered message (Kafka at-least-once)
    is not handled twice — e.g. never double-increments a completion counter.
    TTL-bound by the caller.
    """
    return f"processed:{topic}:{message_key}"
