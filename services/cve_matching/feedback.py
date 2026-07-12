"""Analyst feedback store — Postgres `analyst_feedback` (SCHEMA.md §6) + fake.

Backs the analyst-feedback HTTP endpoint. One row per submitted verdict; the
Task 14 feedback loop later reads this table to recalibrate per-family confidence
thresholds. The Postgres implementation is best-effort/lazy (like `jobs_status`):
if psycopg or the table isn't available it logs and returns None rather than
crashing the request path.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Protocol

from . import config

log = logging.getLogger("cve_matching.feedback")

# Accepted analyst verdicts (kept small + explicit; feeds Task 14 recalibration).
VERDICTS = ("confirmed", "false_positive", "needs_review")


@dataclass
class Feedback:
    job_id: str
    cve_id: str
    verdict: str
    submitted_by: str
    feedback_id: str = ""
    submitted_at: str = ""


class FeedbackStore(Protocol):
    def submit(self, feedback: Feedback) -> Optional[str]: ...

    def list_for_job(self, job_id: str) -> List[Feedback]: ...


def _prepare(feedback: Feedback) -> Feedback:
    if feedback.verdict not in VERDICTS:
        raise ValueError(f"invalid verdict {feedback.verdict!r}; expected one of {VERDICTS}")
    if not feedback.feedback_id:
        feedback.feedback_id = uuid.uuid4().hex
    if not feedback.submitted_at:
        feedback.submitted_at = datetime.now(timezone.utc).isoformat()
    return feedback


class InMemoryFeedbackStore:
    def __init__(self) -> None:
        self._rows: List[Feedback] = []

    def submit(self, feedback: Feedback) -> Optional[str]:
        fb = _prepare(feedback)
        self._rows.append(fb)
        return fb.feedback_id

    def list_for_job(self, job_id: str) -> List[Feedback]:
        return [f for f in self._rows if f.job_id == job_id]


class PostgresFeedbackStore:
    def __init__(self, *, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or config.postgres_dsn()

    def submit(self, feedback: Feedback) -> Optional[str]:
        fb = _prepare(feedback)
        try:
            import psycopg  # lazy
        except Exception:
            log.warning("psycopg unavailable; feedback %s not persisted", fb.feedback_id)
            return None
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO analyst_feedback
                            (feedback_id, job_id, cve_id, verdict, submitted_by, submitted_at)
                        VALUES (%s, %s, %s, %s, %s, %s);
                        """,
                        (fb.feedback_id, fb.job_id, fb.cve_id, fb.verdict, fb.submitted_by, fb.submitted_at),
                    )
            return fb.feedback_id
        except Exception:
            log.warning("could not persist analyst feedback for job %s", fb.job_id, exc_info=True)
            return None

    def list_for_job(self, job_id: str) -> List[Feedback]:
        try:
            import psycopg  # lazy
        except Exception:
            return []
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT feedback_id, job_id, cve_id, verdict, submitted_by, submitted_at "
                        "FROM analyst_feedback WHERE job_id = %s;",
                        (job_id,),
                    )
                    return [
                        Feedback(
                            feedback_id=r[0], job_id=r[1], cve_id=r[2],
                            verdict=r[3], submitted_by=r[4], submitted_at=str(r[5]),
                        )
                        for r in cur.fetchall()
                    ]
        except Exception:
            log.warning("could not list analyst feedback for job %s", job_id, exc_info=True)
            return []
