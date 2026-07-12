"""Task 10 handler test (satisfies backend-architecture.md rule 7).

Feeds the canonical `sample_payloads/firmware.analyzed.json` through
`handle_cve_match` with in-memory fakes and asserts:
  * the emitted `firmware.matched` matches the contract exactly,
  * `matched_children` (NOT completed_children) is incremented,
  * a per-sub-blob SBOM fragment is written to the artifact store,
  * a CONFIRMED exact match resolves from the seeded local corpus.
"""
from __future__ import annotations

import json
import pathlib

from shared import topics
from shared.contracts import FirmwareMatched, Sbom
from shared.redis_keys import completed_children, matched_children

from services.cve_matching import artifacts, runtime
from services.cve_matching.corpus import CveRecord, InMemoryCorpus
from services.cve_matching.embeddings import HashingEmbedder

from _fakes import CapturingContext, FakeNarrator, FakeRedis

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"
BUSYBOX_CPE = "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"


def _load_analyzed() -> dict:
    with open(_SAMPLES / "firmware.analyzed.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_handle_cve_match_full_wiring(monkeypatch):
    # Seed an in-memory corpus with the exact BusyBox CPE from the sample.
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
    store = artifacts.InMemoryArtifactStore()
    redis = FakeRedis()

    runtime.set_repo(repo)
    runtime.set_embedder(HashingEmbedder())
    runtime.set_artifact_store(store)
    runtime.set_narrator(FakeNarrator())
    try:
        # Import here so the @register side-effect is already in place.
        from services.router.handlers.cve_match import handle_cve_match

        payload = _load_analyzed()
        job_id = payload["job_id"]
        sub_blob_id = payload["sub_blob_id"]
        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_ANALYZED, message_key=sub_blob_id)

        handle_cve_match(payload, ctx)

        # 1. Exactly one firmware.matched emitted, on-contract.
        assert len(ctx.emitted) == 1
        topic, emitted = ctx.emitted[0]
        assert topic == topics.FIRMWARE_MATCHED
        FirmwareMatched.model_validate(emitted)
        assert emitted["job_id"] == job_id
        assert emitted["sub_blob_id"] == sub_blob_id

        # 2. The BusyBox CPE resolved to a CONFIRMED exact match.
        confirmed = [m for m in emitted["cve_matches"] if m["cve_id"] == "CVE-2021-28831"]
        assert confirmed and confirmed[0]["confidence_tier"] == "CONFIRMED"
        assert confirmed[0]["similarity_score"] is None

        # 3. matched_children incremented; completed_children untouched.
        assert redis.get(matched_children(job_id)) == "1"
        assert redis.get(completed_children(job_id)) is None

        # 4. SBOM fragment written for this sub-blob, on the §4 contract.
        frag = store.get_json(artifacts.sbom_fragment_key(job_id, sub_blob_id))
        assert frag is not None
        Sbom.model_validate(frag)
        assert frag["job_id"] == job_id
        assert any(
            c["product"] == "busybox" and c["version"] == "1.31.1" for c in frag["components"]
        )
        assert all(c["source_sub_blob_id"] == sub_blob_id for c in frag["components"])
    finally:
        # Reset process singletons so other tests aren't affected.
        runtime.set_repo(None)
        runtime.set_embedder(None)
        runtime.set_artifact_store(None)
        runtime.set_narrator(None)
