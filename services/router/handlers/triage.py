"""Triage stage (Group 2, Task 6).

Consumes ``firmware.uploaded``. Fetches the blob from MinIO, computes its SHA-256,
runs the magic-byte + declared-size pre-check, and dedups via a REAL Redis-bitmap
Bloom filter (``bloom:firmware_hashes``, k=7 double hashing). Then:

  * CLEAN & new  → emit ``firmware.triaged`` (validated OUT by ``ctx.emit``);
  * suspicious / duplicate → route to ``firmware.dlq`` with a reason code.

The heavy lifting lives in ``services.ingestion.triage`` (pure, unit-tested); this
handler is just the I/O wiring. All inter-stage communication is via Kafka
(``ctx.emit``) — never a direct call into another handler.
"""
from __future__ import annotations

import json
import logging

from shared import topics

from services.ingestion import runtime as ingestion_runtime
from services.ingestion.bloom import BloomFilter
from services.ingestion.triage import triage as run_triage

from ..context import HandlerContext
from ..dlq import build_dlq_record
from ..registry import register

log = logging.getLogger("router.triage")


@register(topics.FIRMWARE_UPLOADED)
def handle_triage(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]

    # Bloom filter lives on the shared Redis bitmap (ctx.redis is router-owned).
    bloom = BloomFilter(ctx.redis)
    result = run_triage(payload, blobstore=ingestion_runtime.get_blobstore(), bloom=bloom)

    if not result.clean:
        # Suspicious / duplicate → firmware.dlq with the reason code as `error`.
        log.info("triage reject: job_id=%s reason=%s", job_id, result.reason)
        dlq_record = build_dlq_record(
            ctx.source_topic, json.dumps(payload), result.reason or "rejected"
        )
        ctx.emit(topics.FIRMWARE_DLQ, dlq_record)
        return

    log.info("triage clean: job_id=%s sha256=%s size=%d", job_id, result.sha256, result.size_bytes)
    ctx.emit(topics.FIRMWARE_TRIAGED, result.triaged_payload(job_id))
