"""Validate the extra `firmware.matched` example payloads (for Group 4) against
the contract, and assert the SCHEMA.md §2 conventions hold for each."""
from __future__ import annotations

import json
import pathlib

import pytest

from shared.contracts import ConfidenceTier, FirmwareMatched, MatchedVia

_EXAMPLES_DIR = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads" / "matched_examples"
_FILES = sorted(_EXAMPLES_DIR.glob("firmware.matched.*.json"))


def test_examples_present():
    names = {p.name for p in _FILES}
    assert {
        "firmware.matched.high_confidence.json",
        "firmware.matched.low_confidence.json",
        "firmware.matched.no_findings.json",
    } <= names


@pytest.mark.parametrize("path", _FILES, ids=[p.name for p in _FILES])
def test_example_matches_contract_and_conventions(path):
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    model = FirmwareMatched.model_validate(payload)  # raises if off-contract

    for m in model.cve_matches:
        # NO_MATCH must never be emitted.
        assert m.confidence_tier != ConfidenceTier.NO_MATCH
        if m.matched_via == MatchedVia.EXACT_CPE:
            assert m.similarity_score is None
            assert m.confidence_tier == ConfidenceTier.CONFIRMED
        # llm_rationale only on POSSIBLE / LOW_CONFIDENCE.
        if m.llm_rationale is not None:
            assert m.confidence_tier in (ConfidenceTier.POSSIBLE, ConfidenceTier.LOW_CONFIDENCE)
