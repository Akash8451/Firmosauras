"""Static-analysis stage (Group 2, Task 8).

Consumes ``firmware.extracted``. Fetches the sub-blob bytes from MinIO and runs
multi-encoding string extraction, per-section entropy, a secret/key regex pass
over those same strings, binary hardening-flag parsing, and version-candidate
extraction. Then it ``INCR``s ``job:{job_id}:completed_children`` (the
ANALYSIS-stage counter — distinct from the CVE-match ``matched_children`` the
aggregator gates on, SCHEMA.md §3) and emits ``firmware.analyzed`` (validated OUT
by ``ctx.emit``).

Heavy lifting lives in ``services.static_analysis`` (pure, unit-tested); this
handler is the I/O wiring. The blob store is the SAME one the triage/unpack stages
use (``services.ingestion.runtime``). Inter-stage communication is Kafka-only.
"""
from __future__ import annotations

import logging

from shared import topics
from shared.redis_keys import completed_children

from services.ingestion import runtime as ingestion_runtime
from services.static_analysis.analyze import analyze

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.analysis")

# Cap bytes pulled into memory per sub-blob (hard-constraints: memory is the enemy).
MAX_ANALYZE_BYTES = 64 * 1024 * 1024


def _read_blob(blobstore, key: str, *, cap: int = MAX_ANALYZE_BYTES) -> bytes:
    buf = bytearray()
    for chunk in blobstore.iter_chunks(key):
        buf.extend(chunk)
        if len(buf) >= cap:
            del buf[cap:]
            break
    return bytes(buf)


@register(topics.FIRMWARE_EXTRACTED)
def handle_analysis(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]

    data = _read_blob(ingestion_runtime.get_blobstore(), payload["s3_key"])
    analyzed = analyze(job_id, sub_blob_id, data)

    # Analysis-stage counter (NOT the aggregation gate counter).
    ctx.redis.incr(completed_children(job_id))

    log.info(
        "analysis: job_id=%s sub_blob_id=%s strings=%d versions=%d secrets=%d",
        job_id, sub_blob_id, len(analyzed["strings_found"]),
        len(analyzed["version_candidates"]), len(analyzed["secrets_flagged"]),
    )
    ctx.emit(topics.FIRMWARE_ANALYZED, analyzed)
