"""Task 10 core — the match orchestrator (exact + embedding, tiering, LLM, dedup).

Uses a StubEmbedder returning a fixed query vector and corpus rows with hand-set
embeddings so similarity scores land on exact tier boundaries — no torch, no DB.
"""
from __future__ import annotations

import math

import pytest

from shared.contracts import ConfidenceTier, FirmwareMatched, MatchedVia

from services.cve_matching import matcher
from services.cve_matching.corpus import CveRecord, InMemoryCorpus

from _fakes import FakeNarrator

BUSYBOX_CPE = "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"


class StubEmbedder:
    """Returns a fixed 2-D query vector so cosine similarity == the corpus row's
    first component (rows are seeded as [score, sqrt(1-score^2)])."""

    dim = 2

    def encode(self, text):
        return [1.0, 0.0]

    def encode_batch(self, texts):
        return [self.encode(t) for t in texts]


def _vec_for(score: float):
    return [score, math.sqrt(max(0.0, 1.0 - score * score))]


def _analyzed(version_candidates):
    return {
        "job_id": "job-1",
        "sub_blob_id": "blob-1",
        "strings_found": [],
        "entropy_sections": [],
        "version_candidates": version_candidates,
        "secrets_flagged": [],
        "hardening_flags": {"nx": True, "pie": False, "relro": "partial", "canary": True},
    }


def test_exact_cpe_match_is_confirmed_and_never_calls_llm():
    repo = InMemoryCorpus()
    repo.upsert([
        CveRecord(
            cve_id="CVE-2021-28831",
            cpe_string=BUSYBOX_CPE,
            description="BusyBox invalid free",
            family="busybox",
            embedding=_vec_for(0.99),
        )
    ])
    narrator = FakeNarrator()

    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "busybox", "product": "busybox", "version": "1.31.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=narrator,
    )

    matches = out.matched_payload["cve_matches"]
    assert len(matches) == 1
    m = matches[0]
    assert m["confidence_tier"] == ConfidenceTier.CONFIRMED.value
    assert m["matched_via"] == MatchedVia.EXACT_CPE.value
    assert m["similarity_score"] is None
    assert m["llm_rationale"] is None
    # No LLM call for a CONFIRMED (exact) match.
    assert narrator.calls == []
    # Contract round-trips.
    FirmwareMatched.model_validate(out.matched_payload)


def test_embedding_fallback_tiers_and_drops_no_match():
    repo = InMemoryCorpus()
    repo.upsert([
        CveRecord("CVE-HIGH", "cpe:2.3:a:openssl:openssl:9.9.9:*:*:*:*:*:*:*", "high", "openssl", _vec_for(0.95)),
        CveRecord("CVE-POSSIBLE", "cpe:2.3:a:openssl:openssl:8.8.8:*:*:*:*:*:*:*", "poss", "openssl", _vec_for(0.78)),
        CveRecord("CVE-LOW", "cpe:2.3:a:openssl:openssl:7.7.7:*:*:*:*:*:*:*", "low", "openssl", _vec_for(0.55)),
        CveRecord("CVE-NONE", "cpe:2.3:a:openssl:openssl:6.6.6:*:*:*:*:*:*:*", "none", "openssl", _vec_for(0.30)),
    ])
    narrator = FakeNarrator()

    # A version with no exact corpus row -> forces the embedding fallback path.
    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "openssl", "product": "openssl", "version": "1.1.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=narrator,
    )
    matches = {m["cve_id"]: m for m in out.matched_payload["cve_matches"]}

    # NO_MATCH (0.30) dropped; the other three tiered correctly.
    assert set(matches) == {"CVE-HIGH", "CVE-POSSIBLE", "CVE-LOW"}
    assert matches["CVE-HIGH"]["confidence_tier"] == ConfidenceTier.HIGH_CONFIDENCE.value
    assert matches["CVE-POSSIBLE"]["confidence_tier"] == ConfidenceTier.POSSIBLE.value
    assert matches["CVE-LOW"]["confidence_tier"] == ConfidenceTier.LOW_CONFIDENCE.value

    # All fallback matches are embedding_similarity with a numeric score.
    for m in matches.values():
        assert m["matched_via"] == MatchedVia.EMBEDDING_SIMILARITY.value
        assert isinstance(m["similarity_score"], float)

    # LLM narration ONLY for POSSIBLE + LOW (not HIGH).
    assert matches["CVE-HIGH"]["llm_rationale"] is None
    assert matches["CVE-POSSIBLE"]["llm_rationale"] is not None
    assert matches["CVE-LOW"]["llm_rationale"] is not None
    called_tiers = {c["tier"] for c in narrator.calls}
    assert called_tiers == {ConfidenceTier.POSSIBLE.value, ConfidenceTier.LOW_CONFIDENCE.value}

    FirmwareMatched.model_validate(out.matched_payload)


def test_no_findings_yields_empty_list():
    repo = InMemoryCorpus()  # empty corpus
    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "busybox", "product": "busybox", "version": "1.31.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=FakeNarrator(),
    )
    assert out.matched_payload["cve_matches"] == []
    FirmwareMatched.model_validate(out.matched_payload)


def test_dedup_keeps_highest_tier_across_candidates():
    repo = InMemoryCorpus()
    # Same CVE reachable two ways: exact (CONFIRMED) via busybox, fuzzy (POSSIBLE) via openssl.
    repo.upsert([
        CveRecord("CVE-DUP", BUSYBOX_CPE, "confirmed via cpe", "busybox", _vec_for(0.10)),
        CveRecord("CVE-DUP", "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*", "fuzzy", "openssl", _vec_for(0.78)),
    ])
    out = matcher.match_sub_blob(
        _analyzed([
            {"vendor": "busybox", "product": "busybox", "version": "1.31.1"},
            {"vendor": "openssl", "product": "openssl", "version": "1.1.1"},
        ]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=FakeNarrator(),
    )
    matches = out.matched_payload["cve_matches"]
    dup = [m for m in matches if m["cve_id"] == "CVE-DUP"]
    assert len(dup) == 1
    assert dup[0]["confidence_tier"] == ConfidenceTier.CONFIRMED.value


def test_graceful_degradation_no_narrator():
    repo = InMemoryCorpus()
    repo.upsert([
        CveRecord("CVE-POSSIBLE", "cpe:2.3:a:openssl:openssl:8.8.8:*:*:*:*:*:*:*", "poss", "openssl", _vec_for(0.78)),
    ])
    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "openssl", "product": "openssl", "version": "1.1.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=None,  # LLM layer disabled
    )
    m = out.matched_payload["cve_matches"][0]
    assert m["confidence_tier"] == ConfidenceTier.POSSIBLE.value
    assert m["llm_rationale"] is None  # matching still completes without narration
    FirmwareMatched.model_validate(out.matched_payload)


def test_graceful_degradation_llm_raises():
    repo = InMemoryCorpus()
    repo.upsert([
        CveRecord("CVE-LOW", "cpe:2.3:a:openssl:openssl:7.7.7:*:*:*:*:*:*:*", "low", "openssl", _vec_for(0.55)),
    ])
    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "openssl", "product": "openssl", "version": "1.1.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=FakeNarrator(fail=True),  # every call raises
    )
    m = out.matched_payload["cve_matches"][0]
    assert m["llm_rationale"] is None  # failure swallowed, match still emitted
    FirmwareMatched.model_validate(out.matched_payload)


def test_sbom_components_resolved():
    repo = InMemoryCorpus()
    out = matcher.match_sub_blob(
        _analyzed([{"vendor": "busybox", "product": "busybox", "version": "BusyBox v1.31.1"}]),
        repo=repo,
        embedder=StubEmbedder(),
        narrator=None,
    )
    assert out.sbom_components == [
        {"vendor": "busybox", "product": "busybox", "version": "1.31.1", "source_sub_blob_id": "blob-1"}
    ]
