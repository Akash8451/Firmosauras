"""Confidence tiering — similarity score -> ConfidenceTier (SCHEMA.md §2).

The score->tier mapping uses the PER-FAMILY thresholds from `config` (defaulting
to the locked initial cutoffs 0.90 / 0.70 / 0.50). No hardcoded literals live
here — the Task 14 feedback loop recalibrates a family by installing a new
`ThresholdConfig`, and this function immediately respects it.

CONFIRMED is NOT produced here: it is reserved for exact-CPE matches and is
assigned directly by the matcher (an exact CPE hit has no similarity score).
`NO_MATCH` (score below the low-confidence cutoff) is returned so the caller can
DROP it — it must never be emitted in `cve_matches[]`.
"""
from __future__ import annotations

from typing import Optional

from shared.contracts import ConfidenceTier

from . import config

# Tier ranking for de-duplication: higher wins when the same CVE surfaces twice.
_TIER_RANK = {
    ConfidenceTier.CONFIRMED: 4,
    ConfidenceTier.HIGH_CONFIDENCE: 3,
    ConfidenceTier.POSSIBLE: 2,
    ConfidenceTier.LOW_CONFIDENCE: 1,
    ConfidenceTier.NO_MATCH: 0,
}


def tier_rank(tier: ConfidenceTier) -> int:
    return _TIER_RANK[tier]


def tier_for_score(score: float, family: Optional[str] = None) -> ConfidenceTier:
    """Map an embedding-similarity score to a tier using the family's thresholds.

    Returns NO_MATCH when the score is below the low-confidence cutoff; callers
    must drop NO_MATCH rather than emit it (SCHEMA.md §2 conventions).
    """
    t = config.thresholds_for(family)
    if score >= t.high_confidence:
        return ConfidenceTier.HIGH_CONFIDENCE
    if score >= t.possible:
        return ConfidenceTier.POSSIBLE
    if score >= t.low_confidence:
        return ConfidenceTier.LOW_CONFIDENCE
    return ConfidenceTier.NO_MATCH


def needs_llm_rationale(tier: ConfidenceTier) -> bool:
    """LLM narration is generated ONLY for POSSIBLE / LOW_CONFIDENCE (SCHEMA.md §8).

    Never for CONFIRMED, HIGH_CONFIDENCE, or NO_MATCH.
    """
    return tier in (ConfidenceTier.POSSIBLE, ConfidenceTier.LOW_CONFIDENCE)
