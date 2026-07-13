"""Task 14 — feedback/config HTTP surface + RBAC tests."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from services.cve_matching import config, runtime, security  # noqa: E402
from services.cve_matching.config import DEFAULT_THRESHOLDS  # noqa: E402
from services.cve_matching.feedback import Feedback, InMemoryFeedbackStore  # noqa: E402
from services.integration import feedback_loop  # noqa: E402
from services.integration.http import create_feedback_app  # noqa: E402


@pytest.fixture()
def fs():
    store = InMemoryFeedbackStore()
    runtime.set_feedback_store(store)
    # Recalibration reads from the same store; resolve the seeded CVE to busybox.
    feedback_loop.set_sources(reader=lambda: store.list_for_job("job1"), resolver={"CVE-A": "busybox"}.get)
    try:
        yield store
    finally:
        runtime.set_feedback_store(None)
        feedback_loop.set_sources(None, None)


def test_feedback_endpoint_persists_to_the_store(monkeypatch, fs):
    monkeypatch.delenv("JWT_SECRET", raising=False)  # dev: auth bypassed
    c = TestClient(create_feedback_app())

    resp = c.post("/jobs/job1/feedback", json={"cve_id": "CVE-A", "verdict": "false_positive"})
    assert resp.status_code == 201
    assert resp.json()["feedback_id"]

    rows = fs.list_for_job("job1")
    assert len(rows) == 1
    assert rows[0].verdict == "false_positive" and rows[0].cve_id == "CVE-A"


def test_feedback_endpoint_rejects_bad_verdict(monkeypatch, fs):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    c = TestClient(create_feedback_app())
    resp = c.post("/jobs/job1/feedback", json={"cve_id": "CVE-A", "verdict": "nope"})
    assert resp.status_code == 422


def test_recalibrate_endpoint_shifts_threshold_after_false_positive(monkeypatch, fs):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    c = TestClient(create_feedback_app())

    # An analyst marks a busybox match false-positive...
    c.post("/jobs/job1/feedback", json={"cve_id": "CVE-A", "verdict": "false_positive"})
    # ...then an admin recalibrates.
    resp = c.post("/config/recalibrate")
    assert resp.status_code == 200
    body = resp.json()
    assert "busybox" in body["updated"]

    busybox = config.thresholds_for("busybox")
    assert busybox.high_confidence > DEFAULT_THRESHOLDS.high_confidence

    # And the admin view reflects the recalibrated source.
    rows = {r["family"]: r for r in c.get("/config/thresholds").json()["thresholds"]}
    assert rows["busybox"]["source"] == "recalibrated"


def test_rbac_on_feedback_and_config(monkeypatch, fs):
    monkeypatch.setenv("JWT_SECRET", "secret")
    c = TestClient(create_feedback_app())
    exp = int(time.time()) + 3600

    def tok(role):
        return {"Authorization": f"Bearer {security.encode_jwt({'sub': role, 'role': role, 'exp': exp}, 'secret')}"}

    # reader: no feedback, no config.
    assert c.post("/jobs/job1/feedback", json={"cve_id": "CVE-A", "verdict": "confirmed"}, headers=tok("reader")).status_code == 403
    assert c.get("/config/thresholds", headers=tok("reader")).status_code == 403

    # analyst: feedback yes, config no.
    assert c.post("/jobs/job1/feedback", json={"cve_id": "CVE-A", "verdict": "confirmed"}, headers=tok("analyst")).status_code == 201
    assert c.get("/config/thresholds", headers=tok("analyst")).status_code == 403
    assert c.post("/config/recalibrate", headers=tok("analyst")).status_code == 403

    # admin: everything.
    assert c.get("/config/thresholds", headers=tok("admin")).status_code == 200
    assert c.post("/config/recalibrate", headers=tok("admin")).status_code == 200

    # No token at all -> 401.
    assert c.get("/config/thresholds").status_code == 401
