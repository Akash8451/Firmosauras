"""Task 11 — report aggregation: gate, partial persistence, single report, replay-safety."""
from __future__ import annotations

from datetime import datetime, timezone

from shared import topics
from shared.contracts import FirmwareCompleted, Sbom, validate_payload
from shared.redis_keys import (
    completed_children,
    extraction_complete,
    matched_children,
    total_children,
)

from services.cve_matching import aggregator, artifacts

from _fakes import FakeNarrator, FakeRedis


def _matched(job_id, sub_blob_id, matches=None):
    payload = {"job_id": job_id, "sub_blob_id": sub_blob_id, "cve_matches": matches or []}
    return validate_payload(topics.FIRMWARE_MATCHED, payload)


def _seed_fragment(store, job_id, sub_blob_id, version):
    doc = Sbom(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc),
        components=[
            {
                "vendor": "busybox",
                "product": "busybox",
                "version": version,
                "source_sub_blob_id": sub_blob_id,
            }
        ],
    ).model_dump(mode="json")
    store.put_json(artifacts.sbom_fragment_key(job_id, sub_blob_id), doc)


# --- completion gate -------------------------------------------------------- #
def test_gate_false_without_total():
    redis = FakeRedis()
    assert aggregator.completion_ready(redis, "j") is False


def test_gate_false_without_marker():
    redis = FakeRedis()
    redis.set(total_children("j"), "2")
    redis.incr(matched_children("j"))
    redis.incr(matched_children("j"))
    assert aggregator.completion_ready(redis, "j") is False  # marker not set


def test_gate_false_when_matched_below_total():
    redis = FakeRedis()
    redis.set(total_children("j"), "3")
    redis.set(extraction_complete("j"), "1")
    redis.incr(matched_children("j"))
    assert aggregator.completion_ready(redis, "j") is False


def test_gate_true_and_ignores_completed_children():
    redis = FakeRedis()
    redis.set(total_children("j"), "2")
    redis.set(extraction_complete("j"), "1")
    # completed_children is the WRONG counter; set it high to prove it's ignored.
    redis.set(completed_children("j"), "99")
    redis.incr(matched_children("j"))
    redis.incr(matched_children("j"))
    assert aggregator.completion_ready(redis, "j") is True


# --- partial persistence ---------------------------------------------------- #
def test_partial_persisted_when_gate_not_met():
    from services.cve_matching.reports import InMemoryReportStore

    redis = FakeRedis()
    store = InMemoryReportStore()
    art = artifacts.InMemoryArtifactStore()
    redis.set(total_children("j"), "2")
    redis.set(extraction_complete("j"), "1")
    redis.incr(matched_children("j"))  # only 1 of 2

    emitted = []
    result = aggregator.aggregate(
        _matched("j", "b1", [{"cve_id": "CVE-1", "confidence_tier": "CONFIRMED",
                              "similarity_score": None, "matched_via": "exact_cpe",
                              "llm_rationale": None}]),
        redis=redis, store=store, artifact_store=art,
        emit=lambda t, p: emitted.append((t, p)), narrator=None, mark_complete=lambda j: True,
    )
    assert result is None
    assert emitted == []
    doc = store.get("j")
    assert doc["status"] == "PARTIAL"
    assert "b1" in doc["sub_blobs"]


# --- full job + replay ------------------------------------------------------ #
def test_full_job_exactly_one_report_and_replay_safe():
    from services.cve_matching.reports import InMemoryReportStore

    redis = FakeRedis()
    store = InMemoryReportStore()
    art = artifacts.InMemoryArtifactStore()
    job_id = "jobA"
    subs = ["b1", "b2", "b3"]

    redis.set(total_children(job_id), str(len(subs)))
    redis.set(extraction_complete(job_id), "1")
    for i, sb in enumerate(subs):
        _seed_fragment(art, job_id, sb, f"1.3{i}.0")

    emitted = []
    marks = []

    def emit(t, p):
        emitted.append((t, validate_payload(t, p)))

    def mark(job):
        marks.append(job)
        return True

    results = []
    for sb in subs:
        redis.incr(matched_children(job_id))  # mirrors the cve_match handler
        results.append(
            aggregator.aggregate(
                _matched(job_id, sb, [{"cve_id": "CVE-1", "confidence_tier": "POSSIBLE",
                                       "similarity_score": 0.8, "matched_via": "embedding_similarity",
                                       "llm_rationale": "maybe"}]),
                redis=redis, store=store, artifact_store=art,
                emit=emit, narrator=FakeNarrator(), mark_complete=mark,
            )
        )

    # Only the final matched event (gate satisfied) produces the report.
    assert results[0] is None and results[1] is None
    assert results[2] is not None
    assert len(emitted) == 1
    topic, completed = emitted[0]
    assert topic == topics.FIRMWARE_COMPLETED
    FirmwareCompleted.model_validate(completed)
    assert completed["report_s3_key"] == artifacts.report_key(job_id)
    assert completed["sbom_s3_key"] == artifacts.sbom_key(job_id)

    # Exactly one report doc, marked COMPLETE, with merged components.
    doc = store.get(job_id)
    assert doc["status"] == "COMPLETE"
    assert len(doc["components"]) == 3
    assert doc["summary_stats"]["total_findings"] == 3
    assert doc["executive_summary"] is not None  # narrator ran

    # Final SBOM + report artifacts written and on-contract.
    Sbom.model_validate(art.get_json(artifacts.sbom_key(job_id)))
    assert art.get_json(artifacts.report_key(job_id))["status"] == "COMPLETE"
    assert marks == [job_id]  # Postgres flipped exactly once

    # Replay every matched event again -> NO second report, NO second emit.
    for sb in subs:
        assert aggregator.aggregate(
            _matched(job_id, sb, []),
            redis=redis, store=store, artifact_store=art,
            emit=emit, narrator=None, mark_complete=mark,
        ) is None
    assert len(emitted) == 1  # still exactly one
    assert marks == [job_id]  # not marked again


def test_merge_sbom_components_dedupes():
    frags = [
        ("k1", {"components": [{"vendor": "v", "product": "p", "version": "1", "source_sub_blob_id": "b1"}]}),
        ("k2", {"components": [{"vendor": "v", "product": "p", "version": "1", "source_sub_blob_id": "b1"}]}),  # dup
        ("k3", {"components": [{"vendor": "v", "product": "p", "version": "2", "source_sub_blob_id": "b2"}]}),
    ]
    merged = aggregator.merge_sbom_components(frags)
    assert len(merged) == 2
