"""Frozen event contracts (SCHEMA.md §2) + SBOM artifact shape (SCHEMA.md §4).

Import models from here rather than reaching into submodules:

    from shared.contracts import FirmwareUploaded, FirmwareMatched

`TOPIC_MODELS` maps each Kafka topic name to its payload model and is the backbone
of the CI schema-lint gate (every file in `sample_payloads/` must validate against
its topic's model).
"""
from __future__ import annotations

from typing import Any, Dict, Type

from pydantic import BaseModel

from .. import topics
from .enums import ConfidenceTier, MatchedVia
from .events import (
    CveMatch,
    EntropySection,
    FirmwareAnalyzed,
    FirmwareCompleted,
    FirmwareDlq,
    FirmwareExtracted,
    FirmwareMatched,
    FirmwareTriaged,
    FirmwareUploaded,
    HardeningFlags,
    SecretFlag,
    VersionCandidate,
)
from .sbom import Sbom, SbomComponent

# Single source of truth mapping topic -> payload model. Used by the harness and
# the CI schema-lint gate. Keep in sync with shared/topics.py and SCHEMA.md §1.
TOPIC_MODELS: Dict[str, Type[BaseModel]] = {
    topics.FIRMWARE_UPLOADED: FirmwareUploaded,
    topics.FIRMWARE_TRIAGED: FirmwareTriaged,
    topics.FIRMWARE_EXTRACTED: FirmwareExtracted,
    topics.FIRMWARE_ANALYZED: FirmwareAnalyzed,
    topics.FIRMWARE_MATCHED: FirmwareMatched,
    topics.FIRMWARE_COMPLETED: FirmwareCompleted,
    topics.FIRMWARE_DLQ: FirmwareDlq,
}

def validate_payload(topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a payload against its topic's contract; raise on drift.

    Returns the canonicalized (model-dumped, JSON-mode) dict. Unknown topics are
    rejected so a typo'd topic never silently produces an unvalidated message.
    This is the single validation entry point used by BOTH the router (validate
    IN and OUT, per backend-architecture.md rule 7) and the dev harness.
    """
    model = TOPIC_MODELS.get(topic)
    if model is None:
        raise ValueError(
            f"unknown topic {topic!r}; expected one of {sorted(TOPIC_MODELS)}"
        )
    return model.model_validate(payload).model_dump(mode="json")


__all__ = [
    # enums
    "ConfidenceTier",
    "MatchedVia",
    # event models
    "FirmwareUploaded",
    "FirmwareTriaged",
    "FirmwareExtracted",
    "FirmwareAnalyzed",
    "FirmwareMatched",
    "FirmwareCompleted",
    "FirmwareDlq",
    # sub-models
    "EntropySection",
    "VersionCandidate",
    "SecretFlag",
    "HardeningFlags",
    "CveMatch",
    # sbom
    "Sbom",
    "SbomComponent",
    # registry + helpers
    "TOPIC_MODELS",
    "validate_payload",
]
