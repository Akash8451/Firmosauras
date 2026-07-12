"""Static-analysis stage (Group 2). STUB: emits an empty firmware.analyzed.

Real implementation (Task 8): multi-encoding strings (ASCII + UTF-16LE/BE),
per-section entropy, secret/key regex pass, binary hardening flags, version
candidates; emit firmware.analyzed and INCR job:{id}:completed_children.
"""
from __future__ import annotations

import logging

from shared import topics

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.analysis")


@register(topics.FIRMWARE_EXTRACTED)
def handle_analysis(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]
    log.info("analysis stub: job_id=%s sub_blob_id=%s", job_id, sub_blob_id)
    # NOTE (Group 2): real handler increments completed_children in Redis.
    ctx.emit(
        topics.FIRMWARE_ANALYZED,
        {
            "job_id": job_id,
            "sub_blob_id": sub_blob_id,
            "strings_found": [],
            "entropy_sections": [],
            "version_candidates": [],
            "secrets_flagged": [],
            "hardening_flags": {
                "nx": False,
                "pie": False,
                "relro": "none",
                "canary": False,
            },
        },
    )
