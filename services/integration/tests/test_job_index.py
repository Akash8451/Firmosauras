"""Task 14 — per-job RAG index lifecycle + cross-job isolation tests."""
from __future__ import annotations

from services.cve_matching.embeddings import HashingEmbedder
from services.integration.job_index import JobIndexManager, chunks_from_report


def _mgr(**kw) -> JobIndexManager:
    return JobIndexManager(embedder=HashingEmbedder(), **kw)


def test_build_and_query_returns_only_this_jobs_chunks():
    m = _mgr()
    m.build("jobA", ["busybox 1.31 heap overflow", "dropbear ssh weak key"])
    hits = m.query("jobA", "busybox overflow", top_k=2)
    assert hits
    texts = [t for t, _ in hits]
    assert all("busybox" in t or "dropbear" in t for t in texts)


def test_cross_job_isolation_A_never_sees_B():
    m = _mgr()
    m.build("jobA", ["ALPHA-only secret token from firmware A"])
    m.build("jobB", ["BETA-only credential from firmware B"])

    a_hits = [t for t, _ in m.query("jobA", "BETA credential", top_k=5)]
    b_hits = [t for t, _ in m.query("jobB", "ALPHA token", top_k=5)]

    # Even when A is asked about B's content, it can only return A's own chunks.
    assert all("BETA" not in t for t in a_hits)
    assert any("ALPHA" in t for t in a_hits)
    assert all("ALPHA" not in t for t in b_hits)
    assert any("BETA" in t for t in b_hits)


def test_query_unknown_job_returns_nothing():
    m = _mgr()
    assert m.query("nope", "anything") == []


def test_teardown_frees_the_index():
    m = _mgr()
    m.build("jobA", ["x", "y", "z"])
    assert m.has("jobA") and m.size("jobA") == 3

    assert m.teardown("jobA") is True
    # Resources actually freed: no slot, empty query, not listed.
    assert m.has("jobA") is False
    assert m.size("jobA") == 0
    assert m.query("jobA", "x") == []
    assert "jobA" not in m.active_jobs()
    assert m.teardown("jobA") is False  # already gone


def test_ttl_sweep_tears_down_expired_indexes():
    clock = {"t": 1000.0}
    m = _mgr(ttl_seconds=60, clock=lambda: clock["t"])
    m.build("old", ["stale"])
    clock["t"] = 1100.0  # +100s > ttl
    m.build("fresh", ["current"])

    expired = m.sweep()
    assert expired == ["old"]
    assert m.has("old") is False
    assert m.has("fresh") is True


def test_chunks_from_report_uses_only_that_jobs_material():
    report = {
        "executive_summary": "Two vulnerable components found.",
        "findings": [
            {"cve_id": "CVE-2021-1", "confidence_tier": "CONFIRMED", "llm_rationale": None},
        ],
        "components": [{"vendor": "busybox", "product": "busybox", "version": "1.31.1"}],
    }
    chunks = chunks_from_report(report, extra_strings=["/etc/passwd", ""])
    joined = "\n".join(chunks)
    assert "Executive summary" in joined
    assert "CVE-2021-1" in joined
    assert "busybox busybox 1.31.1" in joined
    assert "/etc/passwd" in joined
    assert "" not in chunks  # blank strings dropped
