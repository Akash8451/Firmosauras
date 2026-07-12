"""Dead-letter helpers.

A message that fails any stage of processing (bad JSON, contract violation, or a
handler exception) is wrapped in a `firmware.dlq` record and its offset is
committed anyway, so one poison message never stalls the partition
(backend-architecture.md rule 3).
"""
from __future__ import annotations

from datetime import datetime, timezone

from shared.contracts import FirmwareDlq


def build_dlq_record(original_topic: str, raw_payload: str, error: str) -> dict:
    """Build a validated `firmware.dlq` payload dict."""
    return FirmwareDlq(
        original_topic=original_topic,
        payload=raw_payload,
        error=error,
        failed_at=datetime.now(timezone.utc),
    ).model_dump(mode="json")
