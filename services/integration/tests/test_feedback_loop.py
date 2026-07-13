"""Task 14 — feedback-loop recalibration tests."""
from __future__ import annotations

from services.cve_matching import config
from services.cve_matching.config import DEFAULT_THRESHOLDS
from services.cve_matching.feedback import Feedback
from services.integration import feedback_loop


def _fb(cve_id: str, verdict: str, job_id: str = "job1") -> Feedback:
    return Feedback(job_id=job_id, cve_id=cve_id, verdict=verdict, submitted_by="analyst-1")


# cve_id -> family for the tests (mirrors what the pg resolver would return).
_RESOLVER = {
    "CVE-A": "busybox",
    "CVE-B": "openssl",
    "CVE-C": "dropbear",
}.get


def test_false_positive_raises_that_familys_thresholds():
    updated = feedback_loop.recalibrate([_fb("CVE-A", "false_positive")], _RESOLVER)

    assert "busybox" in updated
    new = config.thresholds_for("busybox")
    # Stricter than the locked defaults (demands higher similarity to match).
    assert new.high_confidence > DEFAULT_THRESHOLDS.high_confidence
    assert new.possible > DEFAULT_THRESHOLDS.possible
    assert new.low_confidence > DEFAULT_THRESHOLDS.low_confidence
    # Invariant preserved.
    assert 0.0 <= new.low_confidence <= new.possible <= new.high_confidence <= 1.0
    # Other families are untouched.
    assert config.thresholds_for("openssl") == DEFAULT_THRESHOLDS


def test_confirmed_matches_loosen_thresholds_for_recall():
    rows = [_fb("CVE-B", "confirmed") for _ in range(5)]
    updated = feedback_loop.recalibrate(rows, _RESOLVER)

    assert "openssl" in updated
    new = config.thresholds_for("openssl")
    assert new.high_confidence < DEFAULT_THRESHOLDS.high_confidence
    assert new.low_confidence < DEFAULT_THRESHOLDS.low_confidence


def test_mixed_feedback_in_band_keeps_defaults():
    # 1 FP out of 4 decided = 0.25 fp_rate: between loosen(0.1) and stricten(0.5).
    rows = [
        _fb("CVE-C", "confirmed"),
        _fb("CVE-C", "confirmed"),
        _fb("CVE-C", "confirmed"),
        _fb("CVE-C", "false_positive"),
    ]
    updated = feedback_loop.recalibrate(rows, _RESOLVER)
    assert "dropbear" not in updated
    assert config.thresholds_for("dropbear") == DEFAULT_THRESHOLDS


def test_unresolvable_and_needs_review_rows_are_ignored():
    rows = [
        _fb("CVE-UNKNOWN", "false_positive"),  # resolver -> None
        _fb("CVE-A", "needs_review"),           # not a decided verdict
    ]
    updated = feedback_loop.recalibrate(rows, _RESOLVER)
    assert updated == {}


def test_recalibration_is_idempotent():
    rows = [_fb("CVE-A", "false_positive")]
    first = feedback_loop.recalibrate(rows, _RESOLVER)
    second = feedback_loop.recalibrate(rows, _RESOLVER)
    assert first == second  # recomputed from base each run — no unbounded drift


def test_current_thresholds_reports_source():
    feedback_loop.recalibrate([_fb("CVE-A", "false_positive")], _RESOLVER)
    rows = {r["family"]: r for r in feedback_loop.current_thresholds()}
    assert rows["busybox"]["source"] == "recalibrated"
    assert rows["openssl"]["source"] == "default"


def test_recalibrate_now_uses_injected_sources():
    feedback_loop.set_sources(
        reader=lambda: [_fb("CVE-A", "false_positive")],
        resolver=_RESOLVER,
    )
    try:
        updated = feedback_loop.recalibrate_now(install=True)
        assert "busybox" in updated
    finally:
        feedback_loop.set_sources(None, None)
