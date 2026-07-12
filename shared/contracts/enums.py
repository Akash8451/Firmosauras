"""Enumerated types used inside event contracts.

Mirrors SCHEMA.md (`.kiro/steering/schema.md`) exactly. Do not add variant
spellings or reorder semantics without a flagged PR to the schema steering file.
"""
from __future__ import annotations

from enum import Enum


class ConfidenceTier(str, Enum):
    """CVE-match confidence tiers (SCHEMA.md §2, `firmware.matched`).

    Thresholds that map a similarity score to a tier are INITIAL/config-driven
    and recalibrated per component family (Task 14); they are intentionally NOT
    hardcoded in this contract. This enum only pins the tier *names*.

    Note: `NO_MATCH` is defined for completeness but MUST NOT appear in an emitted
    `cve_matches[]` array (see `CveMatch` validators) — a sub-blob with no findings
    emits `cve_matches: []`.
    """

    CONFIRMED = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    POSSIBLE = "POSSIBLE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    NO_MATCH = "NO_MATCH"


class MatchedVia(str, Enum):
    """How a CVE match was resolved (SCHEMA.md §2, `firmware.matched`)."""

    EXACT_CPE = "exact_cpe"
    EMBEDDING_SIMILARITY = "embedding_similarity"
