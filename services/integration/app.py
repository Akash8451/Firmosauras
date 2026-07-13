"""Composed integration app (Task 15) — the single FastAPI process that fronts
the whole system in the no-mock end-to-end run.

It COMPOSES the existing building blocks without editing any other group's files:

    gateway.create_app()              # upload + RBAC + CVE surface (/cve/*)
      + include_router(http.router)        # /jobs/{id}/feedback, /config/*
      + include_router(reports_api.router) # GET /jobs, GET /jobs/{id}/report

On startup it also starts (best-effort) a per-job RAG index builder on its OWN
Kafka consumer group (`firmosaurus-jobindex`), which builds a job's index from
its report the moment `firmware.completed` arrives, plus a periodic TTL sweep.
Both degrade gracefully: if the broker/deps are unavailable the HTTP surface
still serves.

Run (host-native, fat local mode):
    uvicorn services.integration.app:app --port 8000
"""
from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from services.gateway.app import create_app as create_gateway_app

from . import http, reports_api
from .job_index import JobIndexService

log = logging.getLogger("integration.app")

INDEX_CONSUMER_GROUP = "firmosaurus-jobindex"
DEFAULT_SWEEP_INTERVAL = 300  # seconds between TTL sweeps of completed-job indexes


def create_integration_app(
    *, start_index_consumer: bool = True, sweep_interval: int = DEFAULT_SWEEP_INTERVAL
) -> FastAPI:
    """Build the composed app. `start_index_consumer=False` for tests (no broker)."""
    app: FastAPI = create_gateway_app()
    app.include_router(http.router)
    app.include_router(reports_api.router)

    index_service = JobIndexService()
    app.state.index_service = index_service
    app.state.index_consumer = None
    app.state.sweeper_task = None

    if start_index_consumer:
        _wire_index_lifecycle(app, index_service, sweep_interval)

    @app.get("/healthz")
    async def healthz():  # pragma: no cover - trivial
        return {"status": "ok", "surface": "integration"}

    return app


def _wire_index_lifecycle(app: FastAPI, index_service: JobIndexService, sweep_interval: int) -> None:
    """Install a lifespan that runs the per-job index consumer + TTL sweep."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # pragma: no cover - needs a broker
        # Own consumer group so the index builder gets its own copy of the stream
        # (independent of the notifier and the router groups).
        consumer = None
        try:
            from services.notifier.consumer import NotifierConsumer

            consumer = NotifierConsumer(group_id=INDEX_CONSUMER_GROUP)
            thread = threading.Thread(
                target=consumer.run, args=(index_service.on_event,), daemon=True
            )
            thread.start()
            app.state.index_consumer = consumer
            log.info("per-job index builder started (group=%s)", INDEX_CONSUMER_GROUP)
        except Exception:
            log.warning("per-job index consumer not started (broker/deps unavailable)", exc_info=True)

        async def _sweeper() -> None:
            while True:
                await asyncio.sleep(sweep_interval)
                try:
                    expired = index_service.sweep()
                    if expired:
                        log.info("swept %d expired per-job index(es)", len(expired))
                except Exception:
                    log.warning("index sweep failed", exc_info=True)

        sweeper = asyncio.create_task(_sweeper())
        app.state.sweeper_task = sweeper
        try:
            yield
        finally:
            if consumer is not None:
                consumer.stop()
            sweeper.cancel()

    app.router.lifespan_context = lifespan


# Module-level app for `uvicorn services.integration.app:app`.
app = create_integration_app()
