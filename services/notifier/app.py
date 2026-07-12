"""FastAPI WebSocket app for live per-job progress (Task 12).

Wiring:
  * A background thread runs `NotifierConsumer` (own consumer group) and, for each
    `firmware.*` event, folds it through the `ProgressTracker` and publishes the
    resulting snapshot to the `ProgressHub` (thread -> event-loop hop via
    `loop.call_soon_threadsafe`).
  * `GET /ws/jobs/{job_id}` (WebSocket) subscribes a coalescing mailbox and streams
    snapshots. A slow client only ever sees the latest snapshot and never blocks
    the consumer or other clients.

SECURITY: when `JWT_SECRET` is configured, the WebSocket requires a valid token
(query param `?token=...`) whose role can `view` (admin/analyst/reader). In local
dev with no `JWT_SECRET` the endpoint is open — this is called out explicitly so
an unauthenticated progress feed is never shipped silently to a real deployment.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

# Imported at MODULE level (not inside create_app) so FastAPI can resolve the
# `WebSocket` type hint via module globals — otherwise the connection parameter is
# misclassified as a required query parameter.
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status

from services.cve_matching import security

from .consumer import NotifierConsumer
from .hub import ProgressHub
from .progress import ProgressTracker

log = logging.getLogger("notifier.app")


def _make_lifespan():
    """Lifespan that starts the Kafka consumer thread and feeds the hub."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: "FastAPI"):  # pragma: no cover (needs a broker)
        loop = asyncio.get_running_loop()
        consumer = NotifierConsumer()

        def on_event(topic: str, payload: dict) -> None:
            snapshot = app.state.tracker.update(topic, payload)
            if snapshot is not None:
                # Hop back onto the event loop; publish is non-blocking.
                loop.call_soon_threadsafe(app.state.hub.publish, snapshot["job_id"], snapshot)

        thread = threading.Thread(target=consumer.run, args=(on_event,), daemon=True)
        thread.start()
        app.state.consumer = consumer
        app.state.consumer_thread = thread
        log.info("notifier consumer thread started")
        try:
            yield
        finally:
            consumer.stop()

    return lifespan


def create_app(*, hub: Optional[ProgressHub] = None, tracker: Optional[ProgressTracker] = None,
               start_consumer: bool = True):
    """Build the FastAPI app. `hub`/`tracker` are injectable for tests; set
    `start_consumer=False` to skip the background Kafka thread."""
    app = FastAPI(
        title="Firmosaurus Notifier",
        lifespan=_make_lifespan() if start_consumer else None,
    )
    app.state.hub = hub or ProgressHub()
    app.state.tracker = tracker or ProgressTracker()
    app.state.consumer = None
    app.state.consumer_thread = None

    def _authorize(token: Optional[str]) -> bool:
        if not security.auth_enabled():
            return True  # local dev: no secret configured
        try:
            claims = security.verify_token(token)
            security.require_permission(claims, "view")
            return True
        except security.AuthError:
            return False

    @app.websocket("/ws/jobs/{job_id}")
    async def job_progress(websocket: WebSocket, job_id: str):
        token = websocket.query_params.get("token")
        if not _authorize(token):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()
        mailbox = app.state.hub.subscribe(job_id)
        try:
            while True:
                snapshot = await mailbox.get()
                await websocket.send_json(snapshot)
        except WebSocketDisconnect:
            pass
        except Exception:  # network hiccup / client gone — drop this client only
            log.info("notifier client for job %s disconnected", job_id, exc_info=True)
        finally:
            app.state.hub.unsubscribe(job_id, mailbox)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app


# Module-level app for `uvicorn services.notifier.app:app`.
app = create_app()
