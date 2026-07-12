"""Best-effort Postgres `jobs` status update (Task 11).

The `jobs` table DDL is owned by Group 2; the aggregator only needs to flip a
completed job's `status` to COMPLETE and stamp `completed_at`. This is a plain
UPDATE (never a CREATE/ALTER — we don't own the schema). It is best-effort: if
the table isn't present yet (developing without Group 2's migration) it logs and
returns False rather than crashing the aggregation.
"""
from __future__ import annotations

import logging
from typing import Optional

from . import config

log = logging.getLogger("cve_matching.jobs_status")


def mark_job_complete(job_id: str, *, dsn: Optional[str] = None) -> bool:
    """UPDATE jobs SET status='COMPLETE', completed_at=now() WHERE job_id=...

    Returns True on a successful update, False if psycopg is unavailable or the
    update could not be applied (logged, never raised).
    """
    try:
        import psycopg  # lazy
    except Exception:
        log.warning("psycopg unavailable; skipping Postgres job status update for %s", job_id)
        return False

    try:
        with psycopg.connect(dsn or config.postgres_dsn(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE jobs SET status = %s, completed_at = now() WHERE job_id = %s;",
                    ("COMPLETE", job_id),
                )
                return cur.rowcount > 0
    except Exception:
        log.warning("could not update jobs.status for %s", job_id, exc_info=True)
        return False
