"""SBOM artifact contract — SCHEMA.md §4 (`sbom.json`).

Not a Kafka event, but part of the frozen data-shape contract: the Report
Aggregator (Task 11) persists the already-resolved `(vendor, product, version)`
tuples as this artifact alongside the final report. It is a new OUTPUT ARTIFACT,
not new computation (see `.kiro/steering/analysis-modules-rbac.md`).
"""
from __future__ import annotations

from datetime import datetime
from typing import List

from pydantic import BaseModel, ConfigDict, Field


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SbomComponent(_Contract):
    vendor: str
    product: str
    version: str
    source_sub_blob_id: str


class Sbom(_Contract):
    job_id: str
    generated_at: datetime
    components: List[SbomComponent] = Field(default_factory=list)
