"""Task 12 — WebSocket endpoint: streams snapshots, enforces optional JWT auth.

Uses FastAPI's TestClient (skips if httpx isn't available). We seed the hub with a
snapshot BEFORE connecting; `subscribe` then delivers it to the freshly connected
client from within the app's event loop, which keeps the test free of cross-thread
asyncio signalling.
"""
from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from services.cve_matching import security  # noqa: E402
from services.notifier.app import create_app  # noqa: E402
from services.notifier.hub import ProgressHub  # noqa: E402

_SNAP = {"job_id": "job1", "progress": "3/5", "matched": 3, "total": 5, "status": "in_progress"}


def test_ws_streams_snapshot_when_auth_disabled(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    hub = ProgressHub()
    app = create_app(hub=hub, start_consumer=False)
    hub.publish("job1", _SNAP)  # seed last-known snapshot (no subscribers yet)

    client = TestClient(app)
    with client.websocket_connect("/ws/jobs/job1") as ws:
        data = ws.receive_json()
        assert data["job_id"] == "job1"
        assert data["progress"] == "3/5"


def test_ws_rejects_without_token_when_auth_enabled(monkeypatch):
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setenv("JWT_SECRET", "test-secret")
    app = create_app(start_consumer=False)
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/jobs/job1") as ws:
            ws.receive_json()


def test_ws_accepts_valid_reader_token(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    hub = ProgressHub()
    app = create_app(hub=hub, start_consumer=False)
    hub.publish("job1", _SNAP)

    token = security.encode_jwt(
        {"sub": "u1", "role": "reader", "exp": int(time.time()) + 3600}, "test-secret"
    )
    client = TestClient(app)
    with client.websocket_connect(f"/ws/jobs/job1?token={token}") as ws:
        data = ws.receive_json()
        assert data["job_id"] == "job1"
