"""Kafka/Redpanda topic-name constants — SCHEMA.md §1 (pipeline order).

Import these instead of writing magic strings so a topic rename is a single-point
change and typos become import errors, not silent mis-routes.

Partition-keying rule (SCHEMA.md §1), enforced by producers, documented here:
  * job-scoped (keyed by job_id): uploaded, triaged, completed, dlq
  * fan-out (keyed by sub_blob_id): extracted, analyzed, matched
"""
from __future__ import annotations

FIRMWARE_UPLOADED = "firmware.uploaded"
FIRMWARE_TRIAGED = "firmware.triaged"
FIRMWARE_EXTRACTED = "firmware.extracted"
FIRMWARE_ANALYZED = "firmware.analyzed"
FIRMWARE_MATCHED = "firmware.matched"
FIRMWARE_COMPLETED = "firmware.completed"
FIRMWARE_DLQ = "firmware.dlq"

# Topics whose messages are keyed by job_id (one message per job).
JOB_KEYED_TOPICS = (
    FIRMWARE_UPLOADED,
    FIRMWARE_TRIAGED,
    FIRMWARE_COMPLETED,
    FIRMWARE_DLQ,
)

# Fan-out topics keyed by sub_blob_id (the child id), NOT job_id.
SUB_BLOB_KEYED_TOPICS = (
    FIRMWARE_EXTRACTED,
    FIRMWARE_ANALYZED,
    FIRMWARE_MATCHED,
)

# Every topic in pipeline order.
ALL_TOPICS = (
    FIRMWARE_UPLOADED,
    FIRMWARE_TRIAGED,
    FIRMWARE_EXTRACTED,
    FIRMWARE_ANALYZED,
    FIRMWARE_MATCHED,
    FIRMWARE_COMPLETED,
    FIRMWARE_DLQ,
)


def partition_key(topic: str, payload: dict) -> "str | None":
    """Derive the Kafka message key for a payload per the §1 keying rule.

    Fan-out topics are keyed by `sub_blob_id` (preserving per-child parallelism);
    everything else (and the DLQ, when recoverable) is keyed by `job_id`.
    """
    if topic in SUB_BLOB_KEYED_TOPICS:
        return payload.get("sub_blob_id")
    return payload.get("job_id")
