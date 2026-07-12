"""Triage stage (Group 2). STUB: logs and forwards to firmware.triaged.

Real implementation (Task 6): SHA256, Bloom-filter dedup over a Redis bitmap,
magic-byte + declared-size pre-check, emit firmware.triaged or route to DLQ.
"""
from __future__ import annotations

import logging

from shared import topics

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.triage")

_STUB_SHA256 = "0" * 64  # placeholder; real handler computes the digest


@register(topics.FIRMWARE_UPLOADED)
def handle_triage(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    log.info("triage stub: job_id=%s", job_id)
    ctx.emit(
        topics.FIRMWARE_TRIAGED,
        {
            "job_id": job_id,
            "sha256": _STUB_SHA256,
            "is_duplicate": False,
            "size_bytes": 0,
        },
    )
