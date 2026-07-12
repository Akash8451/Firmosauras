"""Task 11 handler test (backend-architecture.md rule 7) — drive the canonical
`sample_payloads/firmware.matched.json` through `handle_aggregate` with a single
sub-blob whose fan-out total is 1, so the completion gate fires and exactly one
`firmware.completed` is emitted."""
from __future__ import annotations

import json
import pathlib

from shared import topics
from shared.contracts import FirmwareCompleted
from shared.redis_keys import extraction_complete, matched_children, total_children

from services.cve_matching import artifacts, runtime
from services.cve_matching.reports import InMemoryReportStore

from _fakes import CapturingContext, FakeNarrator, FakeRedis

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"


def _load_matched() -> dict:
    with open(_SAMPLES / "firmware.matched.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_handle_aggregate_completes_single_child_job():
    payload = _load_matched()
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]

    redis = FakeRedis()
    # Single sub-blob job: total=1, matched about to be 1, extraction done.
    redis.set(total_children(job_id), "1")
    redis.set(extraction_complete(job_id), "1")
    redis.incr(matched_children(job_id))  # the cve_match handler would have done this

    store = InMemoryReportStore()
    art = artifacts.InMemoryArtifactStore()

    runtime.set_report_store(store)
    runtime.set_artifact_store(art)
    runtime.set_narrator(FakeNarrator())
    try:
        from services.router.handlers.aggregate import handle_aggregate

        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_MATCHED, message_key=sub_blob_id)
        handle_aggregate(payload, ctx)

        assert len(ctx.emitted) == 1
        topic, completed = ctx.emitted[0]
        assert topic == topics.FIRMWARE_COMPLETED
        FirmwareCompleted.model_validate(completed)
        assert completed["job_id"] == job_id

        doc = store.get(job_id)
        assert doc["status"] == "COMPLETE"
        # The two CVE matches from the sample are preserved in the report.
        assert doc["summary_stats"]["total_findings"] == 2
        assert art.get_json(artifacts.report_key(job_id))["status"] == "COMPLETE"
    finally:
        runtime.set_report_store(None)
        runtime.set_artifact_store(None)
        runtime.set_narrator(None)


def test_handle_aggregate_waits_when_incomplete():
    payload = _load_matched()
    job_id = payload["job_id"]

    redis = FakeRedis()
    redis.set(total_children(job_id), "5")  # 5 expected, only 1 matched
    redis.set(extraction_complete(job_id), "1")
    redis.incr(matched_children(job_id))

    store = InMemoryReportStore()
    art = artifacts.InMemoryArtifactStore()
    runtime.set_report_store(store)
    runtime.set_artifact_store(art)
    runtime.set_narrator(None)
    try:
        from services.router.handlers.aggregate import handle_aggregate

        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_MATCHED)
        handle_aggregate(payload, ctx)

        assert ctx.emitted == []  # gate not met -> no completion emitted
        assert store.get(job_id)["status"] == "PARTIAL"
    finally:
        runtime.set_report_store(None)
        runtime.set_artifact_store(None)
        runtime.set_narrator(None)
