"""Jobs repository — the Postgres ``jobs`` table (SCHEMA.md §6) + in-memory fake.

    jobs(job_id PK, status, uploaded_by, created_at, completed_at)

Group 2 OWNS this table's DDL (the aggregator in Group 3 only ever ``UPDATE``s
``status``/``completed_at`` — see ``services/cve_matching/jobs_status.py``). The
gateway inserts a row with ``status = 'UPLOADED'`` at upload time; the rest of the
pipeline transitions it.

The real backend is lazy-imported ``psycopg`` (Group 3 already pins
``psycopg[binary]``); unit tests use the in-memory fake so no database is needed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Protocol

from services.cve_matching import config as cve_config

log = logging.getLogger("gateway.jobs")

STATUS_UPLOADED = "UPLOADED"

# DDL owned by Group 2. Applied by ``ensure_schema`` (idempotent) so a fresh
# Postgres is usable without a separate migration step in local dev.
JOBS_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    uploaded_by  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Job:
    job_id: str
    status: str
    uploaded_by: str
    created_at: datetime
    completed_at: Optional[datetime] = None

    def to_public(self) -> dict:
        """Stable JSON shape returned by ``GET /jobs/{id}``."""
        return {
            "job_id": self.job_id,
            "status": self.status,
            "uploaded_by": self.uploaded_by,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class JobsRepo(Protocol):
    def create(self, job_id: str, uploaded_by: str) -> Job: ...

    def get(self, job_id: str) -> Optional[Job]: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests).                                                      #
# --------------------------------------------------------------------------- #
class InMemoryJobsRepo:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}

    def create(self, job_id: str, uploaded_by: str) -> Job:
        if job_id in self._jobs:
            raise ValueError(f"job {job_id} already exists")
        job = Job(
            job_id=job_id,
            status=STATUS_UPLOADED,
            uploaded_by=uploaded_by,
            created_at=_now(),
        )
        self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)


# --------------------------------------------------------------------------- #
# Postgres-backed repo.                                                        #
# --------------------------------------------------------------------------- #
class PostgresJobsRepo:
    def __init__(self, *, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or cve_config.postgres_dsn()
        self._schema_ready = False

    def _connect(self):
        import psycopg  # lazy

        return psycopg.connect(self.dsn, autocommit=True)

    def ensure_schema(self) -> None:
        """Create the ``jobs`` table if it does not exist (idempotent)."""
        if self._schema_ready:
            return
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(JOBS_DDL)
        self._schema_ready = True

    def create(self, job_id: str, uploaded_by: str) -> Job:
        self.ensure_schema()
        job = Job(
            job_id=job_id,
            status=STATUS_UPLOADED,
            uploaded_by=uploaded_by,
            created_at=_now(),
        )
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs (job_id, status, uploaded_by, created_at) "
                "VALUES (%s, %s, %s, %s);",
                (job.job_id, job.status, job.uploaded_by, job.created_at),
            )
        return job

    def get(self, job_id: str) -> Optional[Job]:
        self.ensure_schema()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT job_id, status, uploaded_by, created_at, completed_at "
                "FROM jobs WHERE job_id = %s;",
                (job_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return Job(
            job_id=row[0],
            status=row[1],
            uploaded_by=row[2],
            created_at=row[3],
            completed_at=row[4],
        )
