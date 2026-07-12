"""CVE-match stage (Group 3). STUB: emits firmware.matched with no findings.

Real implementation (Task 10): regex-normalize to CPE, exact lookup then
embedding fallback against local pgvector, confidence tiering, LLM triage ONLY
for POSSIBLE/LOW_CONFIDENCE, write sbom.json, emit firmware.matched, and INCR
job:{id}:matched_children.
"""
from __future__ import annotations

import logging

from shared import topics

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.cve_match")


@register(topics.FIRMWARE_ANALYZED)
def handle_cve_match(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]
    log.info("cve_match stub: job_id=%s sub_blob_id=%s", job_id, sub_blob_id)
    # NOTE (Group 3): real handler increments matched_children in Redis and
    # writes the SBOM artifact. Empty cve_matches == no findings (never NO_MATCH).
    ctx.emit(
        topics.FIRMWARE_MATCHED,
        {
            "job_id": job_id,
            "sub_blob_id": sub_blob_id,
            "cve_matches": [],
        },
    )
