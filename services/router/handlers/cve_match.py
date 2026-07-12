"""CVE-match stage (Group 3, Task 10).

Consumes `firmware.analyzed`, resolves component versions against the LOCAL
pgvector corpus (exact CPE first, embedding-similarity fallback), tiers each
match, and narrates only the uncertain tiers with the optional LLM. Then it:

  * writes a per-sub-blob SBOM fragment to MinIO (the resolved (vendor, product,
    version) tuples — the `firmware.matched` contract has no field for them, so
    the aggregator reads these fragments at completion, SCHEMA.md §4),
  * `INCR job:{job_id}:matched_children` (the CVE-match-stage counter the
    aggregator gates on — NOT `completed_children`, SCHEMA.md §3),
  * emits `firmware.matched` (validated OUT by `ctx.emit`).

The heavy lifting lives in `services.cve_matching.matcher` (pure, unit-tested);
this handler is just the I/O wiring. All inter-stage communication is via Kafka
(`ctx.emit`) — never a direct call into another handler.
"""
from __future__ import annotations

import logging

from shared import topics
from shared.redis_keys import matched_children

from services.cve_matching import artifacts, matcher, runtime

from ..context import HandlerContext
from ..registry import register

log = logging.getLogger("router.cve_match")


@register(topics.FIRMWARE_ANALYZED)
def handle_cve_match(payload: dict, ctx: HandlerContext) -> None:
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]

    result = matcher.match_sub_blob(
        payload,
        repo=runtime.get_repo(),
        embedder=runtime.get_embedder(),
        narrator=runtime.get_narrator(),
    )

    # Persist the SBOM fragment for this sub-blob (assembled by the aggregator).
    fragment = matcher.build_sbom_fragment(job_id, result.sbom_components)
    runtime.get_artifact_store().put_json(
        artifacts.sbom_fragment_key(job_id, sub_blob_id), fragment
    )

    # Increment the CVE-match-stage counter (the aggregation gate counter).
    ctx.redis.incr(matched_children(job_id))

    n_matches = len(result.matched_payload["cve_matches"])
    log.info(
        "cve_match: job_id=%s sub_blob_id=%s matches=%d components=%d",
        job_id, sub_blob_id, n_matches, len(result.sbom_components),
    )

    ctx.emit(topics.FIRMWARE_MATCHED, result.matched_payload)
