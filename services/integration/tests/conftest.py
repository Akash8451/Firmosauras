"""Pytest config for the Group-4 integration tests.

Ensures the repo root is importable and isolates the process-global per-family
threshold overrides so one test's recalibration never leaks into another.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.cve_matching import config  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_family_thresholds():
    """Snapshot + restore config.FAMILY_THRESHOLDS around every test."""
    saved = dict(config.FAMILY_THRESHOLDS)
    config.FAMILY_THRESHOLDS.clear()
    try:
        yield
    finally:
        config.FAMILY_THRESHOLDS.clear()
        config.FAMILY_THRESHOLDS.update(saved)
