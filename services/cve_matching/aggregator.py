"""Report aggregation orchestrator (Task 11) — pure given its dependencies.

Called once per `firmware.matched` event. It records the sub-blob's matches as a
PARTIAL Mongo doc, then checks the completion gate (SCHEMA.md §3):

    assemble ONLY when  matched_children == total_children  AND
                        the `extraction_complete` marker is set.

It gates on `matched_children` (the CVE-match-stage counter), NEVER on
`completed_children` (the analysis-stage counter) — a child can be analyzed but
not yet matched, so gating on the earlier counter fires the aggregator early.

When the gate passes it assembles the final report + SBOM (merging the per-sub-blob
SBOM fragments the CVE-match stage wrote), performs an ATOMIC finalize in Mongo
(so replay / a racing sub-blob never produces a second report), uploads the
artifacts to MinIO, flips the Postgres job to COMPLETE, and returns the validated
`firmware.completed` payload for the handler to emit. Any I/O (Kafka emit) is
injected — the aggregation logic itself stays unit-testable offline.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, List, Optional

from shared import topics
from shared.contracts import Sbom, validate_payload
from shared.redis_keys import extraction_complete, matched_children, total_children

from . import artifacts as artifacts_mod
from . import jobs_status
from .artifacts import ArtifactStore
from .llm import LlmNarrator
from .reports import ReportStore

log = logging.getLogger("cve_matching.aggregator")

_TRUTHY = {"1", "true", "True", "yes"}


def completion_ready(redis, job_id: str) -> bool:
    """The SCHEMA.md §3 gate: matched_children == total_children AND marker set."""
    total_raw = redis.get(total_children(job_id))
    if total_raw is None:
        return False  # unpacker hasn't published the fan-out total yet
    if (redis.get(extraction_complete(job_id)) or "") not in _TRUTHY:
        return False  # extraction still discovering sub-blobs
    try:
        total = int(total_raw)
        matched = int(redis.get(matched_children(job_id)) or 0)
    except (TypeError, ValueError):
        return False
    return total > 0 and matched >= total


def _findings_from_partial(partial: dict) -> List[dict]:
    findings: List[dict] = []
    for sub_blob_id, matches in (partial.get("sub_blobs") or {}).items():
        for m in matches:
            entry = dict(m)
            entry["sub_blob_id"] = sub_blob_id
            findings.append(entry)
    return findings


def merge_sbom_components(fragments: List) -> List[dict]:
    """Merge per-sub-blob SBOM fragments into a deduped component list."""
    seen: set = set()
    out: List[dict] = []
    for _key, doc in fragments:
        for comp in doc.get("components", []):
            ident = (
                comp.get("vendor"),
                comp.get("product"),
                comp.get("version"),
                comp.get("source_sub_blob_id"),
            )
            if ident in seen:
                continue
            seen.add(ident)
            out.append(comp)
    return out


def _summary_stats(findings: List[dict]) -> dict:
    tiers = Counter(f.get("confidence_tier") for f in findings)
    return {
        "total_findings": len(findings),
        "by_tier": dict(tiers),
    }


def _safe_summary(narrator: Optional[LlmNarrator], job_id: str, findings: List[dict]) -> Optional[str]:
    if narrator is None:
        return None
    try:
        return narrator.executive_summary(job_id=job_id, findings=findings)
    except Exception:  # graceful degradation — report completes without narration
        log.warning("executive summary failed for %s; continuing", job_id, exc_info=True)
        return None


def finalize_job(
    job_id: str,
    *,
    store: ReportStore,
    artifact_store: ArtifactStore,
    narrator: Optional[LlmNarrator] = None,
    mark_complete: Callable[[str], bool] = jobs_status.mark_job_complete,
) -> Optional[dict]:
    """Assemble + persist the final report. Returns the `firmware.completed`
    payload if THIS call performed the finalize, else None (already finalized)."""
    partial = store.get(job_id) or {"job_id": job_id, "sub_blobs": {}}
    findings = _findings_from_partial(partial)

    components = merge_sbom_components(artifact_store.list_json(artifacts_mod.sbom_fragment_prefix(job_id)))
    generated_at = datetime.now(timezone.utc).isoformat()

    # Final SBOM artifact (SCHEMA.md §4).
    sbom_doc = Sbom(
        job_id=job_id,
        generated_at=generated_at,
        components=components,  # type: ignore[arg-type]
    ).model_dump(mode="json")

    report_s3_key = artifacts_mod.report_key(job_id)
    sbom_s3_key = artifacts_mod.sbom_key(job_id)

    executive_summary = _safe_summary(narrator, job_id, findings)

    report_doc = {
        "job_id": job_id,
        "status": "COMPLETE",
        "generated_at": generated_at,
        "executive_summary": executive_summary,
        "summary_stats": _summary_stats(findings),
        "components": components,
        "findings": findings,
        "report_s3_key": report_s3_key,
        "sbom_s3_key": sbom_s3_key,
    }

    # ATOMIC finalize FIRST — only the winner proceeds to emit, so replay / a
    # racing sub-blob can't produce a second firmware.completed.
    won = store.finalize(job_id, report_doc)
    if not won:
        log.info("job %s already finalized; skipping duplicate completion", job_id)
        return None

    # Idempotent artifact writes (safe even if re-run).
    artifact_store.put_json(sbom_s3_key, sbom_doc)
    artifact_store.put_json(report_s3_key, report_doc)

    # Best-effort Postgres status flip (Group 2 owns the table DDL).
    mark_complete(job_id)

    return validate_payload(
        topics.FIRMWARE_COMPLETED,
        {
            "job_id": job_id,
            "status": "COMPLETE",
            "report_s3_key": report_s3_key,
            "sbom_s3_key": sbom_s3_key,
        },
    )


def aggregate(
    matched_payload: dict,
    *,
    redis,
    store: ReportStore,
    artifact_store: ArtifactStore,
    emit: Callable[[str, dict], None],
    narrator: Optional[LlmNarrator] = None,
    mark_complete: Callable[[str], bool] = jobs_status.mark_job_complete,
) -> Optional[dict]:
    """Handle one `firmware.matched`: record partial, gate, and finalize if ready.

    Returns the emitted `firmware.completed` payload, or None when the job is not
    yet complete (partial persisted) or was already finalized elsewhere.
    """
    job_id = matched_payload["job_id"]
    sub_blob_id = matched_payload["sub_blob_id"]
    cve_matches = matched_payload.get("cve_matches", [])

    # 1. Persist partial result (idempotent per sub-blob).
    store.record_sub_blob(job_id, sub_blob_id, cve_matches)

    # 2. Completion gate.
    if not completion_ready(redis, job_id):
        log.info("job %s not complete yet; partial persisted", job_id)
        return None

    # 3. Assemble + finalize (atomic) + emit.
    completed = finalize_job(
        job_id,
        store=store,
        artifact_store=artifact_store,
        narrator=narrator,
        mark_complete=mark_complete,
    )
    if completed is None:
        return None
    emit(topics.FIRMWARE_COMPLETED, completed)
    log.info("job %s COMPLETE: emitted firmware.completed", job_id)
    return completed
