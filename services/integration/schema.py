"""Group-4 integration schema bootstrap.

The `jobs` table self-creates via `PostgresJobsRepo.ensure_schema()` (Group 2) and
`cve_corpus` via `PgVectorCorpus.ensure_schema()` (Group 3), but `analyst_feedback`
(SCHEMA.md §6) had no equivalent — `PostgresFeedbackStore.submit()` just INSERTs and
swallows the error if the table is missing. On a fresh Postgres that means feedback
submission silently no-ops and the Task 14 recalibration loop always reads `[]`.

Rather than edit Group 3's `feedback.py`, the integration layer (which owns the
final wiring) ensures the table exists at app startup. Idempotent
`CREATE TABLE IF NOT EXISTS`, best-effort: a missing driver or an unreachable DB
logs and returns False instead of blocking startup.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from services.cve_matching import config

log = logging.getLogger("integration.schema")

# Matches services/cve_matching/feedback.py's INSERT columns and SCHEMA.md §6.
FEEDBACK_DDL = """
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id  TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

# Speeds up the per-job feedback listing the endpoint/recalibration use.
FEEDBACK_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS analyst_feedback_job_idx ON analyst_feedback (job_id);"
)

# Factory: dsn -> a connection context manager (with a .cursor() context manager).
ConnectFactory = Callable[[str], object]


def _default_connect(dsn: str):
    import psycopg  # lazy

    return psycopg.connect(dsn, autocommit=True)


def ensure_feedback_schema(
    *, dsn: Optional[str] = None, connect_factory: Optional[ConnectFactory] = None
) -> bool:
    """Create `analyst_feedback` (+ its index) if absent. Best-effort; True on success."""
    factory = connect_factory or _default_connect
    try:
        with factory(dsn or config.postgres_dsn()) as conn:
            with conn.cursor() as cur:
                cur.execute(FEEDBACK_DDL)
                cur.execute(FEEDBACK_INDEX_DDL)
        log.info("analyst_feedback schema ensured")
        return True
    except Exception:
        log.warning("could not ensure analyst_feedback schema (continuing)", exc_info=True)
        return False
