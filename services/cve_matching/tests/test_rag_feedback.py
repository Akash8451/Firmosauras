"""Unit tests for RAG context assembly + the analyst feedback store."""
from __future__ import annotations

import pytest

from services.cve_matching import rag
from services.cve_matching.corpus import CveRecord, InMemoryCorpus
from services.cve_matching.embeddings import HashingEmbedder
from services.cve_matching.feedback import Feedback, InMemoryFeedbackStore
from services.cve_matching.reports import InMemoryReportStore


def test_build_context_combines_findings_and_corpus():
    repo = InMemoryCorpus()
    emb = HashingEmbedder()
    repo.upsert([
        CveRecord("CVE-2021-28831", "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*",
                  "BusyBox invalid free", "busybox", emb.encode("busybox invalid free")),
    ])
    rs = InMemoryReportStore()
    rs.record_sub_blob("job1", "b1", [{
        "cve_id": "CVE-2021-28831", "confidence_tier": "POSSIBLE",
        "similarity_score": 0.8, "matched_via": "embedding_similarity", "llm_rationale": None,
    }])

    ctx = rag.build_context("job1", "busybox free bug", repo=repo, embedder=emb, report_store=rs)

    assert ctx.job_id == "job1"
    assert ctx.job_status == "PARTIAL"
    assert ctx.finding_count == 1
    assert "CVE-2021-28831" in ctx.sources
    assert any("CVE-2021-28831" in chunk for chunk in ctx.chunks)


def test_build_context_missing_report_is_safe():
    repo = InMemoryCorpus()
    ctx = rag.build_context("nope", "q", repo=repo, embedder=HashingEmbedder(), report_store=InMemoryReportStore())
    assert ctx.job_id == "nope"
    assert ctx.finding_count == 0


def test_feedback_store_submit_and_list():
    store = InMemoryFeedbackStore()
    fid = store.submit(Feedback(job_id="j", cve_id="CVE-1", verdict="confirmed", submitted_by="analyst-1"))
    assert fid
    rows = store.list_for_job("j")
    assert len(rows) == 1
    assert rows[0].feedback_id == fid
    assert rows[0].submitted_at  # stamped


def test_feedback_store_rejects_bad_verdict():
    store = InMemoryFeedbackStore()
    with pytest.raises(ValueError):
        store.submit(Feedback(job_id="j", cve_id="C", verdict="nonsense", submitted_by="u"))
