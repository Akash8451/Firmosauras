"""Task 14 — per-job RAG vector index lifecycle.

When a job completes we build a small, in-memory vector index over THAT job's own
material (its extracted strings + resolved findings) so the RAG chat can ground
answers in the specific firmware in question. The index is:

  * strictly job-scoped — each job's vectors live in their own slot keyed by
    ``job_id``; a query for job A can only ever read job A's slot, so it can NEVER
    retrieve job B's data (cross-job isolation is structural, not a filter that
    could be forgotten);
  * torn down on demand or after a TTL — ``teardown``/``sweep`` drop the slot,
    freeing the vectors so many completed jobs don't accumulate unbounded memory
    (WSL2 8 GB budget, hard-constraints.md).

Embedding uses the same ``Embedder`` abstraction as the CVE core
(all-MiniLM-L6-v2 in prod, the deterministic ``HashingEmbedder`` in tests), so no
new model is introduced. Retrieval is air-gapped: cosine similarity over the local
per-job vectors, no network call.
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from services.cve_matching.embeddings import Embedder, get_embedder

log = logging.getLogger("integration.job_index")

DEFAULT_TTL_SECONDS = 3600  # completed-job index lifetime before auto-teardown


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    dot = na = nb = 0.0
    for i in range(n):
        dot += a[i] * b[i]
        na += a[i] * a[i]
        nb += b[i] * b[i]
    if na == 0.0 or nb == 0.0:
        return 0.0
    sim = dot / (math.sqrt(na) * math.sqrt(nb))
    return 0.0 if sim < 0.0 else (1.0 if sim > 1.0 else sim)


@dataclass
class _Entry:
    text: str
    vector: List[float]


@dataclass
class _JobIndex:
    job_id: str
    entries: List[_Entry] = field(default_factory=list)
    created_at: float = 0.0


def chunks_from_report(report: Optional[dict], extra_strings: Optional[Sequence[str]] = None) -> List[str]:
    """Assemble the text chunks for a job's index from its report + extracted strings.

    Uses only that job's own material: the executive summary, each finding
    (cve id + tier + rationale), the resolved SBOM components, and any extracted
    strings passed in from the analysis stage.
    """
    chunks: List[str] = []
    if report:
        summary = report.get("executive_summary")
        if summary:
            chunks.append(f"Executive summary: {summary}")
        for f in report.get("findings", []) or []:
            bits = [f.get("cve_id"), f.get("confidence_tier"), f.get("llm_rationale")]
            text = " ".join(str(b) for b in bits if b)
            if text:
                chunks.append(f"Finding: {text}")
        for c in report.get("components", []) or []:
            ident = f"{c.get('vendor', '')} {c.get('product', '')} {c.get('version', '')}".strip()
            if ident:
                chunks.append(f"Component: {ident}")
    for s in extra_strings or []:
        s = (s or "").strip()
        if s:
            chunks.append(s)
    return chunks


class JobIndexManager:
    """Builds, serves, and tears down per-job RAG indexes with cross-job isolation."""

    def __init__(
        self,
        *,
        embedder: Optional[Embedder] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._embedder = embedder
        self._ttl = ttl_seconds
        self._clock = clock
        self._indexes: Dict[str, _JobIndex] = {}

    def _emb(self) -> Embedder:
        return self._embedder or get_embedder()

    # -- lifecycle ---------------------------------------------------------- #
    def build(self, job_id: str, chunks: Sequence[str]) -> int:
        """(Re)build the index for one job from its own chunks. Returns entry count."""
        emb = self._emb()
        entries = [_Entry(text=c, vector=emb.encode(c)) for c in chunks if c and c.strip()]
        self._indexes[job_id] = _JobIndex(job_id=job_id, entries=entries, created_at=self._clock())
        log.info("built per-job index job=%s entries=%d", job_id, len(entries))
        return len(entries)

    def teardown(self, job_id: str) -> bool:
        """Drop a job's index, freeing its vectors. True if one existed."""
        existed = self._indexes.pop(job_id, None) is not None
        if existed:
            log.info("tore down per-job index job=%s", job_id)
        return existed

    def sweep(self) -> List[str]:
        """Tear down every index older than the TTL. Returns the job_ids removed."""
        now = self._clock()
        expired = [jid for jid, idx in self._indexes.items() if now - idx.created_at > self._ttl]
        for jid in expired:
            self.teardown(jid)
        return expired

    # -- retrieval (strictly job-scoped) ------------------------------------ #
    def query(self, job_id: str, question: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Return the top-k chunks FOR THIS JOB ONLY (never another job's data)."""
        idx = self._indexes.get(job_id)
        if idx is None or not idx.entries:
            return []
        qv = self._emb().encode(question)
        scored = [(e.text, _cosine(qv, e.vector)) for e in idx.entries]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[: max(0, top_k)]

    # -- introspection ------------------------------------------------------ #
    def has(self, job_id: str) -> bool:
        return job_id in self._indexes

    def size(self, job_id: str) -> int:
        idx = self._indexes.get(job_id)
        return len(idx.entries) if idx else 0

    def active_jobs(self) -> List[str]:
        return list(self._indexes.keys())


# --------------------------------------------------------------------------- #
# Process-wide singleton. The integration app (Task 15) builds a job's index on #
# `firmware.completed` and periodically calls `sweep()`; tests inject a fake.   #
# --------------------------------------------------------------------------- #
_manager: Optional[JobIndexManager] = None


def get_manager() -> JobIndexManager:
    global _manager
    if _manager is None:
        _manager = JobIndexManager()
    return _manager


def set_manager(manager: Optional[JobIndexManager]) -> None:
    global _manager
    _manager = manager


class JobIndexService:
    """Wires the per-job index into the pipeline: build on `firmware.completed`.

    Given a report-store getter, it assembles a job's index from that job's own
    report the moment the job completes, and exposes a `sweep()` the app can call
    on a timer for TTL teardown. Best-effort: a build failure for one job never
    breaks the pipeline.
    """

    def __init__(self, *, manager: Optional[JobIndexManager] = None, report_store_getter: Optional[Callable[[], object]] = None) -> None:
        self._manager = manager
        self._report_store_getter = report_store_getter

    def _mgr(self) -> JobIndexManager:
        return self._manager or get_manager()

    def _report_store(self):
        if self._report_store_getter is not None:
            return self._report_store_getter()
        from services.cve_matching import runtime  # lazy
        return runtime.get_report_store()

    def build_for_job(self, job_id: str) -> int:
        report = self._report_store().get(job_id)
        chunks = chunks_from_report(report)
        return self._mgr().build(job_id, chunks)

    def on_event(self, topic: str, payload: dict) -> None:
        """Callback for a `firmware.*` consumer: build the index on completion."""
        from shared import topics as _t  # lazy

        if topic == _t.FIRMWARE_COMPLETED:
            job_id = payload.get("job_id")
            if job_id:
                try:
                    n = self.build_for_job(job_id)
                    log.info("job %s completed: built per-job index (%d chunks)", job_id, n)
                except Exception:
                    log.warning("failed to build per-job index for %s", job_id, exc_info=True)

    def sweep(self) -> List[str]:
        return self._mgr().sweep()
