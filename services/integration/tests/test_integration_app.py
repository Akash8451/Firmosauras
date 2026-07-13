"""Task 15 — composed integration app + no-mock pipeline-chain tests.

The chain test runs the REAL CVE-match and aggregate handler code (no mocking of
pipeline logic) wired to in-memory infra fakes, proving:
  * firmware.analyzed -> firmware.matched -> firmware.completed produces a report,
  * that report is visible through the composed app's GET /jobs/{id}/report,
  * replaying the completed job produces NO duplicate report (idempotent),
  * the per-job RAG index is built on completion and is job-scoped.
"""
from __future__ import annotations

import json
import pathlib
from typing import Dict, List, Optional, Tuple

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from shared import topics  # noqa: E402
from shared.contracts import validate_payload  # noqa: E402
from shared.redis_keys import extraction_complete, matched_children, total_children  # noqa: E402

from services.cve_matching import artifacts, runtime  # noqa: E402
from services.cve_matching.corpus import CveRecord, InMemoryCorpus  # noqa: E402
from services.cve_matching.embeddings import HashingEmbedder  # noqa: E402
from services.cve_matching.feedback import InMemoryFeedbackStore  # noqa: E402
from services.cve_matching.reports import InMemoryReportStore  # noqa: E402
from services.router.context import HandlerContext  # noqa: E402
from services.integration import reports_api  # noqa: E402
from services.integration.app import create_integration_app  # noqa: E402
from services.integration.job_index import JobIndexManager, JobIndexService  # noqa: E402

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"
BUSYBOX_CPE = "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"


class _FakeRedis:
    def __init__(self) -> None:
        self._s: Dict[str, str] = {}

    def get(self, k):
        return self._s.get(k)

    def set(self, k, v, **_kw):
        self._s[k] = str(v)
        return True

    def incr(self, k, amount=1):
        self._s[k] = str(int(self._s.get(k, "0")) + amount)
        return int(self._s[k])


class _CapturingContext(HandlerContext):
    def __init__(self, redis, source_topic):
        self.emitted: List[Tuple[str, dict]] = []

        def _emit(topic, payload):
            self.emitted.append((topic, validate_payload(topic, payload)))

        super().__init__(emit=_emit, redis=redis, source_topic=source_topic, message_key=None)


def _seed_runtime():
    repo = InMemoryCorpus()
    repo.upsert([
        CveRecord(
            cve_id="CVE-2021-28831",
            cpe_string=BUSYBOX_CPE,
            description="BusyBox 1.31.1 invalid free in decompress_gunzip.c",
            family="busybox",
            embedding=HashingEmbedder().encode("busybox 1.31.1 invalid free"),
        )
    ])
    store = InMemoryReportStore()
    art = artifacts.InMemoryArtifactStore()
    runtime.set_repo(repo)
    runtime.set_embedder(HashingEmbedder())
    runtime.set_report_store(store)
    runtime.set_artifact_store(art)
    runtime.set_feedback_store(InMemoryFeedbackStore())
    runtime.set_narrator(None)
    return store


def _reset_runtime():
    for setter in (
        runtime.set_repo, runtime.set_embedder, runtime.set_report_store,
        runtime.set_artifact_store, runtime.set_feedback_store, runtime.set_narrator,
    ):
        setter(None)
    reports_api.set_jobs_lister(None)


@pytest.fixture()
def wiring(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)  # dev: auth permissive
    store = _seed_runtime()
    app = create_integration_app(start_index_consumer=False)
    try:
        yield TestClient(app), store
    finally:
        _reset_runtime()


def _run_chain(store) -> Tuple[str, _FakeRedis]:
    """Drive analyzed -> matched -> completed through the REAL handlers."""
    from services.router.handlers.cve_match import handle_cve_match
    from services.router.handlers.aggregate import handle_aggregate

    analyzed = json.loads((_SAMPLES / "firmware.analyzed.json").read_text(encoding="utf-8"))
    job_id = analyzed["job_id"]

    redis = _FakeRedis()
    # Single-child job: the unpacker would have set these.
    redis.set(total_children(job_id), "1")
    redis.set(extraction_complete(job_id), "1")

    # Stage 1: CVE match (increments matched_children, emits firmware.matched).
    ctx1 = _CapturingContext(redis, topics.FIRMWARE_ANALYZED)
    handle_cve_match(analyzed, ctx1)
    assert redis.get(matched_children(job_id)) == "1"
    matched_topic, matched_payload = ctx1.emitted[0]
    assert matched_topic == topics.FIRMWARE_MATCHED

    # Stage 2: aggregate (gate passes -> finalize -> emit firmware.completed).
    ctx2 = _CapturingContext(redis, topics.FIRMWARE_MATCHED)
    handle_aggregate(matched_payload, ctx2)
    assert [t for t, _ in ctx2.emitted] == [topics.FIRMWARE_COMPLETED]
    return job_id, redis


def test_report_visible_through_composed_app_after_real_chain(wiring):
    client, store = wiring
    job_id, _redis = _run_chain(store)

    resp = client.get(f"/jobs/{job_id}/report")
    assert resp.status_code == 200
    report = resp.json()
    assert report["status"] == "COMPLETE"
    assert report["summary_stats"]["total_findings"] >= 1
    assert any(f["cve_id"] == "CVE-2021-28831" for f in report["findings"])


def test_replay_completed_job_produces_no_duplicate_report(wiring):
    _client, store = wiring
    job_id, redis = _run_chain(store)

    # Re-deliver the same firmware.matched: aggregate must NOT emit a 2nd completion.
    from services.router.handlers.aggregate import handle_aggregate

    matched = json.loads((_SAMPLES / "firmware.matched.json").read_text(encoding="utf-8"))
    # Align the sample's job to our completed job so the replay targets it.
    matched["job_id"] = job_id
    redis.set(total_children(job_id), "1")
    ctx = _CapturingContext(redis, topics.FIRMWARE_MATCHED)
    handle_aggregate(matched, ctx)

    assert ctx.emitted == []  # already finalized -> no duplicate firmware.completed
    assert store.get(job_id)["status"] == "COMPLETE"


def test_jobs_list_endpoint(wiring):
    client, _store = wiring
    reports_api.set_jobs_lister(lambda: [
        {"job_id": "j1", "status": "COMPLETE", "uploaded_by": "u", "created_at": "2026-07-14T00:00:00Z", "completed_at": None},
    ])
    resp = client.get("/jobs")
    assert resp.status_code == 200
    jobs = resp.json()["jobs"]
    assert len(jobs) == 1 and jobs[0]["job_id"] == "j1"


def test_report_404_for_unknown_job(wiring):
    client, _store = wiring
    assert client.get("/jobs/does-not-exist/report").status_code == 404


def test_composed_app_exposes_all_group4_surfaces(wiring):
    client, _store = wiring
    # feedback loop + config surfaces are mounted alongside the gateway routes.
    assert client.post("/jobs/j1/feedback", json={"cve_id": "C", "verdict": "confirmed"}).status_code == 201
    assert client.get("/config/thresholds").status_code == 200
    # gateway's CVE chat surface is still present.
    assert client.post("/cve/chat", json={"job_id": "j1", "question": "hi"}).status_code == 200


def test_per_job_index_built_on_completion_is_job_scoped(wiring):
    _client, store = wiring
    job_id, _redis = _run_chain(store)

    mgr = JobIndexManager(embedder=HashingEmbedder())
    svc = JobIndexService(manager=mgr, report_store_getter=lambda: store)
    # Simulate the firmware.completed event the index consumer would receive.
    svc.on_event(topics.FIRMWARE_COMPLETED, {"job_id": job_id})

    assert mgr.has(job_id)
    hits = mgr.query(job_id, "busybox", top_k=5)
    assert hits  # grounded in this job's own material
    # A different job has no index -> strictly isolated.
    assert mgr.query("other-job", "busybox") == []
