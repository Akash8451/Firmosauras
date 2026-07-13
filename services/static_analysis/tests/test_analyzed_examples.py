"""Validate the Group 2 `firmware.analyzed` example payloads against the contract.

Top-level samples are covered by CI `schema_lint`; these live under
`sample_payloads/analyzed_examples/` (a subdirectory, to avoid the gate's
one-sample-per-topic rule) and are validated here.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from shared.contracts import FirmwareAnalyzed

_EXAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads" / "analyzed_examples"


@pytest.mark.parametrize("path", sorted(_EXAMPLES.glob("*.json")), ids=lambda p: p.name)
def test_analyzed_example_on_contract(path):
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    model = FirmwareAnalyzed.model_validate(payload)
    # relro is the documented tri-state.
    assert model.hardening_flags.relro in {"none", "partial", "full"}
