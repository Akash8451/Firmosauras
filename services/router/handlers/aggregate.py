"""Aggregate stage (Group 3, Task 11).

Consumes `firmware.matched`. Records each sub-blob's matches as a PARTIAL report
document, then applies the completion gate (SCHEMA.md §3):

    assemble ONLY when  matched_children == total_children  AND
                        the `extraction_complete` marker is set.

It gates on `matched_children` (NOT `completed_children`). When the gate passes
it assembles the final report + SBOM, does an ATOMIC Mongo finalize (replay-safe:
exactly one report per job), uploads artifacts to MinIO, flips the Postgres job
status to COMPLETE, and emits `firmware.completed`. Until then it just persists
the partial and waits for more `firmware.matched` events.

Orchestration lives in `services.cve_matching.aggregator` (pure, unit-tested);
this handler is the I/O wiring. Inter-stage communication is Kafka-only via
`ctx.emit` — no direct handler-to-handler calls.
"""
from __future__ import annotations

import logging

from shared import topics

from services.cve_matching import aggregator, runtime

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.aggregate")


@register(topics.FIRMWARE_MATCHED)
def handle_aggregate(payload: dict, ctx: HandlerContext) -> None:
    aggregator.aggregate(
        payload,
        redis=ctx.redis,
        store=runtime.get_report_store(),
        artifact_store=runtime.get_artifact_store(),
        narrator=runtime.get_narrator(),
        emit=ctx.emit,
    )
