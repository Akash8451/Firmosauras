"""Task 10 support — version normalization + confidence tiering."""
from __future__ import annotations

from shared.contracts import ConfidenceTier

from services.cve_matching import config, normalize, tiering


# --- normalization ---------------------------------------------------------- #
def test_normalize_extracts_clean_version_from_banner():
    comp = normalize.normalize_candidate(
        {"vendor": "busybox", "product": "busybox", "version": "BusyBox v1.31.1 (2020-04-14)"}
    )
    assert comp.version == "1.31.1"
    assert comp.family == "busybox"


def test_normalize_openssl_letter_suffix_version():
    comp = normalize.normalize_candidate(
        {"vendor": "openssl", "product": "openssl", "version": "OpenSSL 1.0.2h  3 May 2016"}
    )
    assert comp.version == "1.0.2h"
    assert comp.family == "openssl"


def test_normalize_out_of_scope_family_none():
    comp = normalize.normalize_candidate(
        {"vendor": "microsoft", "product": "windows", "version": "10.0"}
    )
    assert comp.family is None
    assert comp.version == "10.0"


def test_candidate_cpes_builds_family_combos():
    comp = normalize.normalize_candidate(
        {"vendor": "busybox", "product": "busybox", "version": "1.31.1"}
    )
    cpes = normalize.candidate_cpes(comp)
    assert "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*" in cpes


def test_candidate_cpes_empty_without_version():
    comp = normalize.normalize_candidate({"vendor": "busybox", "product": "busybox", "version": "n/a"})
    assert comp.version is None
    assert normalize.candidate_cpes(comp) == []


# --- tiering ---------------------------------------------------------------- #
def test_tier_for_score_boundaries_default():
    assert tiering.tier_for_score(0.95) == ConfidenceTier.HIGH_CONFIDENCE
    assert tiering.tier_for_score(0.90) == ConfidenceTier.HIGH_CONFIDENCE
    assert tiering.tier_for_score(0.89) == ConfidenceTier.POSSIBLE
    assert tiering.tier_for_score(0.70) == ConfidenceTier.POSSIBLE
    assert tiering.tier_for_score(0.69) == ConfidenceTier.LOW_CONFIDENCE
    assert tiering.tier_for_score(0.50) == ConfidenceTier.LOW_CONFIDENCE
    assert tiering.tier_for_score(0.49) == ConfidenceTier.NO_MATCH


def test_tier_respects_per_family_override():
    custom = config.ThresholdConfig(high_confidence=0.80, possible=0.60, low_confidence=0.40)
    config.set_family_thresholds("busybox", custom)
    try:
        # 0.85 is only HIGH under the lowered busybox thresholds.
        assert tiering.tier_for_score(0.85, "busybox") == ConfidenceTier.HIGH_CONFIDENCE
        assert tiering.tier_for_score(0.85, "openssl") == ConfidenceTier.POSSIBLE
    finally:
        config.FAMILY_THRESHOLDS.clear()


def test_needs_llm_rationale_only_uncertain_tiers():
    assert tiering.needs_llm_rationale(ConfidenceTier.POSSIBLE)
    assert tiering.needs_llm_rationale(ConfidenceTier.LOW_CONFIDENCE)
    assert not tiering.needs_llm_rationale(ConfidenceTier.CONFIRMED)
    assert not tiering.needs_llm_rationale(ConfidenceTier.HIGH_CONFIDENCE)
    assert not tiering.needs_llm_rationale(ConfidenceTier.NO_MATCH)
