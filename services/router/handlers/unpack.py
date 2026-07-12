"""Unpack stage (Group 2). STUB: emits a single firmware.extracted sub-blob.

Real implementation (Task 7): sandboxed extraction (setrlimit + timeout +
SIGKILL), layered zip-bomb defenses, fan-out one firmware.extracted per child
keyed by sub_blob_id, INCR job:{id}:total_children, and set the
job:{id}:extraction_complete marker once discovery finishes.
"""
from __future__ import annotations

import logging
import uuid

from shared import topics

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.unpack")


@register(topics.FIRMWARE_TRIAGED)
def handle_unpack(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    sub_blob_id = str(uuid.uuid4())
    log.info("unpack stub: job_id=%s -> sub_blob_id=%s", job_id, sub_blob_id)
    # NOTE (Group 2): real handler increments total_children and sets the
    # extraction_complete marker in Redis; the stub only forwards one child.
    ctx.emit(
        topics.FIRMWARE_EXTRACTED,
        {
            "job_id": job_id,
            "sub_blob_id": sub_blob_id,
            "s3_key": f"extracted/{job_id}/{sub_blob_id}.bin",
            "parent_blob_id": None,
        },
    )
