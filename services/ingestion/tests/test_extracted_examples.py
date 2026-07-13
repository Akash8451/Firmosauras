"""Validate the Group 2 `firmware.extracted` example payloads against the contract.

The top-level `sample_payloads/*.json` files are covered by the CI `schema_lint`
gate; the additional examples under `sample_payloads/extracted_examples/` live in a
subdirectory (so they don't break the gate's one-sample-per-topic rule) and are
validated here instead.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from shared.contracts import FirmwareExtracted

_EXAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads" / "extracted_examples"


@pytest.mark.parametrize("path", sorted(_EXAMPLES.glob("*.json")), ids=lambda p: p.name)
def test_extracted_example_on_contract(path):
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    model = FirmwareExtracted.model_validate(payload)
    assert model.s3_key == f"extracted/{model.job_id}/{model.sub_blob_id}.bin"
