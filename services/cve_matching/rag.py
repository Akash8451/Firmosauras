"""RAG retrieval for the CVE chat endpoint (Task 13 surface, Group 3).

Retrieval is AIR-GAPPED: the question is embedded locally and matched against the
local pgvector corpus (no network on the retrieve path, hard-constraints.md). The
retrieved CVE descriptions plus the job's own findings form the grounding context.
The external LLM (SCHEMA.md §8) is used ONLY to phrase an answer over that context
and degrades gracefully — if it's unavailable the caller still gets the grounded
sources back.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from .corpus import CorpusRepository
from .embeddings import Embedder
from .reports import ReportStore

log = logging.getLogger("cve_matching.rag")


@dataclass
class RagContext:
    job_id: str
    chunks: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)   # cve_ids used as grounding
    job_status: Optional[str] = None
    finding_count: int = 0


def build_context(
    job_id: str,
    question: str,
    *,
    repo: CorpusRepository,
    embedder: Embedder,
    report_store: ReportStore,
    top_k: int = 5,
) -> RagContext:
    """Assemble grounding context for a question about a specific job.

    Combines (a) the job's own report findings (so the answer is scoped to the
    firmware in question) with (b) the top-k most relevant CVE descriptions from
    the local corpus for the question text.
    """
    ctx = RagContext(job_id=job_id)

    report = None
    try:
        report = report_store.get(job_id)
    except Exception:
        log.warning("could not load report for job %s", job_id, exc_info=True)

    job_cve_ids: set = set()
    if report:
        ctx.job_status = report.get("status")
        # A finalized report exposes flat `findings`; a PARTIAL doc keeps matches
        # under `sub_blobs` — support both so chat works mid-job and post-completion.
        findings = report.get("findings")
        if not findings:
            findings = [
                m
                for matches in (report.get("sub_blobs") or {}).values()
                for m in matches
            ]
        ctx.finding_count = len(findings)
        for f in findings:
            cve_id = f.get("cve_id")
            if cve_id:
                job_cve_ids.add(cve_id)
        if findings:
            summary = report.get("executive_summary")
            if summary:
                ctx.chunks.append(f"Report summary: {summary}")
            tiers = ", ".join(
                f"{f.get('cve_id')} [{f.get('confidence_tier')}]" for f in findings[:20]
            )
            ctx.chunks.append(f"This job's findings: {tiers}")

    # Air-gapped semantic retrieval over the local corpus.
    try:
        qvec = embedder.encode(question)
        for rec, score in repo.similarity_search(qvec, top_k=top_k):
            ctx.chunks.append(f"{rec.cve_id} ({rec.cpe_string}): {rec.description}")
            if rec.cve_id not in ctx.sources:
                ctx.sources.append(rec.cve_id)
    except Exception:
        log.warning("corpus retrieval failed for job %s", job_id, exc_info=True)

    # Surface the job's own CVEs first in the source list.
    for cve_id in job_cve_ids:
        if cve_id not in ctx.sources:
            ctx.sources.insert(0, cve_id)

    return ctx
