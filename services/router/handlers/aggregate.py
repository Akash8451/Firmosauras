"""Aggregate stage (Group 3). STUB: emits a terminal firmware.completed.

Real implementation (Task 11): gate on
`matched_children == total_children` AND the `extraction_complete` marker (NOT
`completed_children`), idempotent Mongo upsert by job_id, upload report + sbom to
MinIO, set Postgres status COMPLETE, then emit firmware.completed.
"""
from __future__ import annotations

import logging

from shared import topics

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.aggregate")


@register(topics.FIRMWARE_MATCHED)
def handle_aggregate(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    log.info("aggregate stub: job_id=%s", job_id)
    # NOTE (Group 3): real handler gates on matched_children == total_children AND
    # the extraction_complete marker before assembling the report. The stub emits
    # immediately since the skeleton fans out exactly one child per job.
    ctx.emit(
        topics.FIRMWARE_COMPLETED,
        {
            "job_id": job_id,
            "status": "COMPLETE",
            "report_s3_key": f"reports/{job_id}/report.json",
            "sbom_s3_key": f"reports/{job_id}/sbom.json",
        },
    )
