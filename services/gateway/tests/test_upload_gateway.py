"""Task 5 — Upload Gateway + 3-tier RBAC.

Covers (per the Task 5 checklist):
  * the presigned-multipart upload flow succeeds end-to-end;
  * ``firmware.uploaded`` is emitted ONLY after the completion callback (never at
    upload-creation time);
  * the emitted event and the ``jobs`` row match the schema;
  * auth failures (no token, wrong role) are rejected;
  * all three RBAC role boundaries (admin / analyst / reader) are enforced.
"""
from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from services.cve_matching import security  # noqa: E402
from services.gateway import runtime  # noqa: E402
from services.gateway.app import create_app  # noqa: E402
from services.gateway.events import InMemoryEmitter  # noqa: E402
from services.gateway.jobs import STATUS_UPLOADED, InMemoryJobsRepo  # noqa: E402
from services.gateway.storage import InMemoryStorage  # noqa: E402
from shared import topics  # noqa: E402
from shared.contracts import validate_payload  # noqa: E402


def _seed(monkeypatch, *, auth: bool = False):
    """Install in-memory fakes; enable/disable auth via JWT_SECRET."""
    if auth:
        monkeypatch.setenv("JWT_SECRET", "test-secret")
    else:
        monkeypatch.delenv("JWT_SECRET", raising=False)
    storage = InMemoryStorage()
    jobs = InMemoryJobsRepo()
    emitter = InMemoryEmitter()
    runtime.set_storage(storage)
    runtime.set_jobs_repo(jobs)
    runtime.set_emitter(emitter)
    return storage, jobs, emitter


@pytest.fixture(autouse=True)
def _reset_runtime():
    yield
    runtime.reset()


def _token(role: str) -> dict:
    exp = int(time.time()) + 3600
    tok = security.encode_jwt({"sub": f"u-{role}", "role": role, "exp": exp}, "test-secret")
    return {"Authorization": f"Bearer {tok}"}


# --------------------------------------------------------------------------- #
# Happy path + no-early-emit.                                                  #
# --------------------------------------------------------------------------- #
def test_upload_flow_succeeds_and_emits_only_after_completion(monkeypatch):
    storage, jobs, emitter = _seed(monkeypatch)
    client = TestClient(create_app())

    # 1) Create the upload — job row created, presigned URLs returned, NO emit.
    resp = client.post("/uploads", json={"filename": "fw.bin", "size_bytes": 2048, "part_count": 2})
    assert resp.status_code == 201
    body = resp.json()
    job_id = body["job_id"]
    assert body["s3_key"] == f"raw-uploads/{job_id}/original.bin"
    assert len(body["parts"]) == 2
    assert all(p["url"].startswith("http") for p in body["parts"])

    # Job row persisted as UPLOADED.
    job = jobs.get(job_id)
    assert job is not None and job.status == STATUS_UPLOADED

    # CRITICAL: nothing emitted before the completion callback.
    assert emitter.emitted == []
    assert storage.object_exists(f"raw-uploads/{job_id}/original.bin") is False

    # 2) Complete the upload — object now exists, event emitted exactly once.
    resp = client.post(
        f"/uploads/{job_id}/complete",
        json={"upload_id": body["upload_id"], "parts": [
            {"part_number": 1, "etag": "etag-1"},
            {"part_number": 2, "etag": "etag-2"},
        ]},
    )
    assert resp.status_code == 200
    assert resp.json()["emitted"] is True

    assert len(emitter.emitted) == 1
    topic, payload = emitter.emitted[0]
    assert topic == topics.FIRMWARE_UPLOADED
    # Emitted payload matches the frozen firmware.uploaded contract exactly.
    assert validate_payload(topics.FIRMWARE_UPLOADED, payload) == payload
    assert payload["job_id"] == job_id
    assert payload["s3_key"] == f"raw-uploads/{job_id}/original.bin"
    assert payload["uploaded_by"] == "dev"


def test_complete_unknown_job_is_404(monkeypatch):
    _seed(monkeypatch)
    client = TestClient(create_app())
    resp = client.post(
        "/uploads/does-not-exist/complete",
        json={"upload_id": "x", "parts": [{"part_number": 1, "etag": "e"}]},
    )
    assert resp.status_code == 404


def test_get_job_returns_stable_shape(monkeypatch):
    _seed(monkeypatch)
    client = TestClient(create_app())
    job_id = client.post("/uploads", json={"filename": "f", "size_bytes": 1}).json()["job_id"]

    resp = client.get(f"/jobs/{job_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"job_id", "status", "uploaded_by", "created_at", "completed_at"}
    assert body["job_id"] == job_id
    assert body["status"] == STATUS_UPLOADED
    assert body["completed_at"] is None


def test_get_unknown_job_is_404(monkeypatch):
    _seed(monkeypatch)
    client = TestClient(create_app())
    assert client.get("/jobs/nope").status_code == 404


# --------------------------------------------------------------------------- #
# Auth failures.                                                               #
# --------------------------------------------------------------------------- #
def test_upload_without_token_rejected(monkeypatch):
    _seed(monkeypatch, auth=True)
    client = TestClient(create_app())
    resp = client.post("/uploads", json={"filename": "f", "size_bytes": 1})
    assert resp.status_code == 401


def test_upload_with_bad_signature_rejected(monkeypatch):
    _seed(monkeypatch, auth=True)
    client = TestClient(create_app())
    bad = security.encode_jwt({"sub": "x", "role": "admin"}, "WRONG-secret")
    resp = client.post(
        "/uploads", json={"filename": "f", "size_bytes": 1},
        headers={"Authorization": f"Bearer {bad}"},
    )
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Three-tier RBAC boundaries.                                                  #
# --------------------------------------------------------------------------- #
def test_reader_cannot_upload_but_can_view(monkeypatch):
    _seed(monkeypatch, auth=True)
    client = TestClient(create_app())

    # reader is denied upload.
    resp = client.post("/uploads", json={"filename": "f", "size_bytes": 1}, headers=_token("reader"))
    assert resp.status_code == 403

    # Seed a job as admin, then confirm reader CAN view it.
    admin_job = client.post(
        "/uploads", json={"filename": "f", "size_bytes": 1}, headers=_token("admin")
    ).json()["job_id"]
    resp = client.get(f"/jobs/{admin_job}", headers=_token("reader"))
    assert resp.status_code == 200


def test_analyst_can_upload(monkeypatch):
    _seed(monkeypatch, auth=True)
    client = TestClient(create_app())
    resp = client.post("/uploads", json={"filename": "f", "size_bytes": 1}, headers=_token("analyst"))
    assert resp.status_code == 201


def test_admin_can_upload(monkeypatch):
    _seed(monkeypatch, auth=True)
    client = TestClient(create_app())
    resp = client.post("/uploads", json={"filename": "f", "size_bytes": 1}, headers=_token("admin"))
    assert resp.status_code == 201


def test_reader_denied_completion_callback(monkeypatch):
    storage, jobs, emitter = _seed(monkeypatch, auth=True)
    client = TestClient(create_app())
    job_id = client.post(
        "/uploads", json={"filename": "f", "size_bytes": 1}, headers=_token("admin")
    ).json()["job_id"]

    # reader may not drive the completion callback either.
    resp = client.post(
        f"/uploads/{job_id}/complete",
        json={"upload_id": "x", "parts": [{"part_number": 1, "etag": "e"}]},
        headers=_token("reader"),
    )
    assert resp.status_code == 403
    assert emitter.emitted == []
