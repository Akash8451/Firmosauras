"""Task (CVE HTTP surface) — RAG chat + analyst feedback endpoints and RBAC."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from services.cve_matching import runtime, security  # noqa: E402
from services.cve_matching.corpus import CveRecord, InMemoryCorpus  # noqa: E402
from services.cve_matching.embeddings import HashingEmbedder  # noqa: E402
from services.cve_matching.feedback import InMemoryFeedbackStore  # noqa: E402
from services.cve_matching.reports import InMemoryReportStore  # noqa: E402
from services.gateway.cve_api import create_cve_app  # noqa: E402


class _Narrator:
    def rag_answer(self, *, question, context_chunks):
        return f"grounded answer over {len(context_chunks)} chunk(s)"

    def triage_rationale(self, **k):
        return None

    def executive_summary(self, **k):
        return None


def _seed_runtime(*, narrator=_Narrator()):
    repo = InMemoryCorpus()
    emb = HashingEmbedder()
    repo.upsert([
        CveRecord("CVE-2021-28831", "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*",
                  "BusyBox invalid free in decompress_gunzip.c", "busybox",
                  emb.encode("busybox invalid free decompress")),
    ])
    rs = InMemoryReportStore()
    rs.record_sub_blob("job1", "b1", [{
        "cve_id": "CVE-2021-28831", "confidence_tier": "POSSIBLE",
        "similarity_score": 0.8, "matched_via": "embedding_similarity", "llm_rationale": "maybe",
    }])
    fs = InMemoryFeedbackStore()
    runtime.set_repo(repo)
    runtime.set_embedder(emb)
    runtime.set_report_store(rs)
    runtime.set_feedback_store(fs)
    runtime.set_narrator(narrator)
    return fs


def _reset_runtime():
    for setter in (
        runtime.set_repo, runtime.set_embedder, runtime.set_report_store,
        runtime.set_feedback_store, runtime.set_narrator,
    ):
        setter(None)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)  # auth bypassed (dev)
    fs = _seed_runtime()
    try:
        yield TestClient(create_cve_app()), fs
    finally:
        _reset_runtime()


def test_chat_returns_grounded_answer_with_sources(client):
    c, _fs = client
    resp = c.post("/cve/chat", json={"job_id": "job1", "question": "is busybox vulnerable?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["grounded"] is True
    assert body["answer"] is not None
    assert "CVE-2021-28831" in body["sources"]
    assert body["job_status"] == "PARTIAL"


def test_chat_degrades_gracefully_without_llm(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    _seed_runtime(narrator=None)  # LLM disabled
    try:
        c = TestClient(create_cve_app())
        resp = c.post("/cve/chat", json={"job_id": "job1", "question": "q"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["answer"] is None          # no narration
        assert "CVE-2021-28831" in body["sources"]  # but grounded sources still returned
    finally:
        _reset_runtime()


def test_feedback_accepted_and_persisted(client):
    c, fs = client
    resp = c.post("/cve/feedback", json={
        "job_id": "job1", "cve_id": "CVE-2021-28831", "verdict": "false_positive"
    })
    assert resp.status_code == 201
    assert resp.json()["feedback_id"]
    rows = fs.list_for_job("job1")
    assert len(rows) == 1 and rows[0].verdict == "false_positive"


def test_feedback_rejects_invalid_verdict(client):
    c, _fs = client
    resp = c.post("/cve/feedback", json={"job_id": "job1", "cve_id": "X", "verdict": "bogus"})
    assert resp.status_code == 422


def test_rbac_enforced_when_auth_enabled(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    _seed_runtime()
    try:
        c = TestClient(create_cve_app())
        exp = int(time.time()) + 3600

        # No token -> 401.
        assert c.post("/cve/chat", json={"job_id": "job1", "question": "q"}).status_code == 401

        reader = security.encode_jwt({"sub": "r", "role": "reader", "exp": exp}, "test-secret")
        analyst = security.encode_jwt({"sub": "a", "role": "analyst", "exp": exp}, "test-secret")
        rh = {"Authorization": f"Bearer {reader}"}
        ah = {"Authorization": f"Bearer {analyst}"}

        # reader can view (chat) but cannot submit feedback.
        assert c.post("/cve/chat", json={"job_id": "job1", "question": "q"}, headers=rh).status_code == 200
        assert c.post("/cve/feedback", json={"job_id": "job1", "cve_id": "C", "verdict": "confirmed"}, headers=rh).status_code == 403

        # analyst can submit feedback.
        assert c.post("/cve/feedback", json={"job_id": "job1", "cve_id": "C", "verdict": "confirmed"}, headers=ah).status_code == 201
    finally:
        _reset_runtime()
