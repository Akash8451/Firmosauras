"""Unpack stage (Group 2, Task 7).

Consumes ``firmware.triaged``. Downloads the blob, extracts it inside a
sandboxed, job-namespaced temp dir with four independent zip-bomb defenses, and
FANS OUT one ``firmware.extracted`` per leaf sub-blob (keyed by ``sub_blob_id``,
NOT ``job_id`` — SCHEMA.md §1). For each child it uploads the bytes to MinIO and
``INCR``s ``job:{job_id}:total_children``; once discovery finishes it SETs the
``job:{job_id}:extraction_complete`` marker so the aggregator's gate can pass.

A tripped defense (zip-slip / symlink / recursion-depth / decompression-ratio /
sandbox timeout) routes the job to ``firmware.dlq`` with the layer name as the
reason code. The temp dir is always cleaned up by ``extract_job``'s ``finally``.

Heavy lifting lives in ``services.ingestion`` (pure, unit-tested); this handler is
the I/O wiring. Inter-stage communication is Kafka-only via ``ctx.emit``.
"""
from __future__ import annotations

import json
import logging

from shared import topics
from shared.redis_keys import extraction_complete, total_children

from services.ingestion import runtime as ingestion_runtime
from services.ingestion import unpack as unpack_logic
from services.ingestion.defenses import ExtractionError

from ..context import HandlerContext
from ..dlq import build_dlq_record
from ..registry import register

log = logging.getLogger("router.unpack")


@register(topics.FIRMWARE_TRIAGED)
def handle_unpack(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    blobstore = ingestion_runtime.get_blobstore()
    extractor = ingestion_runtime.get_extractor()

    count = 0
    try:
        with unpack_logic.extract_job(payload, blobstore=blobstore, extractor=extractor) as sub_blobs:
            for sb in sub_blobs:
                # Upload the extracted child, then fan out (keyed by sub_blob_id).
                blobstore.put_bytes(sb.s3_key(job_id), sb.read_bytes())
                ctx.redis.incr(total_children(job_id))
                ctx.emit(topics.FIRMWARE_EXTRACTED, sb.extracted_payload(job_id))
                count += 1
    except ExtractionError as exc:
        # A zip-bomb defense tripped → DLQ with the layer as the reason code.
        log.warning("unpack rejected job_id=%s layer=%s: %s", job_id, exc.layer, exc)
        dlq_record = build_dlq_record(ctx.source_topic, json.dumps(payload), f"{exc.layer}: {exc}")
        ctx.emit(topics.FIRMWARE_DLQ, dlq_record)
        return

    # Only after ALL children are counted + emitted: set the completion marker so
    # the aggregator never fires while sub-blobs are still being discovered.
    ctx.redis.set(extraction_complete(job_id), 1)
    log.info("unpack complete: job_id=%s sub_blobs=%d", job_id, count)
