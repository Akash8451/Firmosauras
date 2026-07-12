"""Pydantic event contracts — one model per Kafka event in SCHEMA.md §2.

These are the frozen, drift-proof interface between every pipeline stage. Handlers
MUST validate payloads both IN and OUT against these models (see
`.kiro/steering/backend-architecture.md` rule 7). Field names and types match
SCHEMA.md (`.kiro/steering/schema.md`) exactly.

`extra="forbid"` is deliberate: an unexpected field turns silent schema drift into
a loud, immediate validation error — far cheaper to catch here than as a mystery
bug at integration time.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import ConfidenceTier, MatchedVia


class _Contract(BaseModel):
    """Base for every event model: reject unknown fields to catch drift loudly."""

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# firmware.uploaded                                                            #
# --------------------------------------------------------------------------- #
class FirmwareUploaded(_Contract):
    """Emitted by the Upload Gateway ONLY after the S3/MinIO completion callback
    confirms the object exists (SCHEMA.md §2). Keyed by `job_id`.
    """

    job_id: str
    s3_key: str
    uploaded_by: str
    uploaded_at: datetime


# --------------------------------------------------------------------------- #
# firmware.triaged                                                             #
# --------------------------------------------------------------------------- #
class FirmwareTriaged(_Contract):
    """Emitted by the triage handler after hashing + Bloom dedup + magic-byte /
    size pre-check (SCHEMA.md §2). Keyed by `job_id`.
    """

    job_id: str
    sha256: str
    is_duplicate: bool
    size_bytes: int = Field(ge=0)

    @field_validator("sha256")
    @classmethod
    def _sha256_is_hex64(cls, v: str) -> str:
        v = v.strip()
        if len(v) != 64 or not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("sha256 must be a 64-character hex string")
        return v.lower()


# --------------------------------------------------------------------------- #
# firmware.extracted (fan-out: one event per sub-blob)                         #
# --------------------------------------------------------------------------- #
class FirmwareExtracted(_Contract):
    """One event per discovered sub-blob (SCHEMA.md §2). Keyed by `sub_blob_id`
    (the child id) — NOT `job_id` — to preserve fan-out parallelism.
    """

    job_id: str
    sub_blob_id: str
    s3_key: str
    parent_blob_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# firmware.analyzed                                                            #
# --------------------------------------------------------------------------- #
class EntropySection(_Contract):
    offset: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)
    flagged_packed: bool


class VersionCandidate(_Contract):
    vendor: str
    product: str
    version: str


class SecretFlag(_Contract):
    type: str
    context: str


class HardeningFlags(_Contract):
    """Binary hardening flags (SCHEMA.md §2). `relro` is a string tri-state
    (`none` / `partial` / `full`); the rest are booleans."""

    nx: bool
    pie: bool
    relro: str
    canary: bool


class FirmwareAnalyzed(_Contract):
    """Emitted by the static-analysis handler (SCHEMA.md §2). Keyed by
    `sub_blob_id`."""

    job_id: str
    sub_blob_id: str
    strings_found: List[str] = Field(default_factory=list)
    entropy_sections: List[EntropySection] = Field(default_factory=list)
    version_candidates: List[VersionCandidate] = Field(default_factory=list)
    secrets_flagged: List[SecretFlag] = Field(default_factory=list)
    hardening_flags: HardeningFlags


# --------------------------------------------------------------------------- #
# firmware.matched                                                             #
# --------------------------------------------------------------------------- #
class CveMatch(_Contract):
    """A single CVE match entry inside `firmware.matched.cve_matches[]`.

    Contract-level invariants enforced (SCHEMA.md §2 conventions):
      * `matched_via == exact_cpe`  => `similarity_score` is null AND tier is CONFIRMED.
      * `matched_via == embedding_similarity` => `similarity_score` is a float in
        [0, 1] AND tier is NOT CONFIRMED (CONFIRMED is exact-only).
      * `NO_MATCH` entries are never emitted — a sub-blob with no findings uses
        `cve_matches: []`.
      * `llm_rationale` is populated ONLY for POSSIBLE / LOW_CONFIDENCE; it is null
        for CONFIRMED and HIGH_CONFIDENCE.

    The numeric score->tier thresholds are config-driven / per-family recalibrated
    (Task 14) and are deliberately NOT validated here.
    """

    cve_id: str
    confidence_tier: ConfidenceTier
    similarity_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    matched_via: MatchedVia
    llm_rationale: Optional[str] = None

    @model_validator(mode="after")
    def _check_invariants(self) -> "CveMatch":
        if self.confidence_tier == ConfidenceTier.NO_MATCH:
            raise ValueError(
                "NO_MATCH must not be emitted in cve_matches[]; use an empty list"
            )

        if self.matched_via == MatchedVia.EXACT_CPE:
            if self.similarity_score is not None:
                raise ValueError(
                    "similarity_score must be null when matched_via == exact_cpe"
                )
            if self.confidence_tier != ConfidenceTier.CONFIRMED:
                raise ValueError(
                    "matched_via == exact_cpe requires confidence_tier == CONFIRMED"
                )
        else:  # embedding_similarity
            if self.similarity_score is None:
                raise ValueError(
                    "similarity_score is required when matched_via == embedding_similarity"
                )
            if self.confidence_tier == ConfidenceTier.CONFIRMED:
                raise ValueError(
                    "CONFIRMED is reserved for exact_cpe matches, not embedding_similarity"
                )

        rationale_allowed = self.confidence_tier in (
            ConfidenceTier.POSSIBLE,
            ConfidenceTier.LOW_CONFIDENCE,
        )
        if self.llm_rationale is not None and not rationale_allowed:
            raise ValueError(
                "llm_rationale is only populated for POSSIBLE / LOW_CONFIDENCE tiers"
            )
        return self


class FirmwareMatched(_Contract):
    """Emitted by the CVE-match handler (SCHEMA.md §2). Keyed by `sub_blob_id`.

    `cve_matches` may be empty (no findings). It never contains NO_MATCH entries.
    """

    job_id: str
    sub_blob_id: str
    cve_matches: List[CveMatch] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# firmware.completed                                                           #
# --------------------------------------------------------------------------- #
class FirmwareCompleted(_Contract):
    """Emitted by the Report Aggregator once the completion gate passes
    (`matched_children == total_children` AND `extraction_complete`). Keyed by
    `job_id` (SCHEMA.md §2)."""

    job_id: str
    status: Literal["COMPLETE"] = "COMPLETE"
    report_s3_key: str
    sbom_s3_key: str


# --------------------------------------------------------------------------- #
# firmware.dlq                                                                 #
# --------------------------------------------------------------------------- #
class FirmwareDlq(_Contract):
    """Dead-letter record for any message that fails a handler (SCHEMA.md §2).
    Keyed by `job_id` where one is recoverable from the failing payload."""

    original_topic: str
    payload: str
    error: str
    failed_at: datetime
