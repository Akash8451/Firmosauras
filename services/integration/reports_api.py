"""Group-4 read surface — job list + assembled report (frontend-facing).

Two endpoints the Task 13 dashboard needs that the base gateway doesn't expose:

  * ``GET /jobs``               (perm ``view``) — list jobs so the dashboard can
    show new uploads from any user and let the operator pick one.
  * ``GET /jobs/{id}/report``   (perm ``view``) — the assembled report document
    (Mongo ``reports``, SCHEMA.md §7) for the report viewer.

Both are mounted onto the gateway app via ``include_router`` (see
``integration.app``) — no gateway files are edited. Auth reuses the shared
``services.cve_matching.security`` mechanism. The Postgres job lister is
best-effort and injectable so tests need no database.
"""
from __future__ import annotations

import logging
from typing import Callable, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from services.cve_matching import config as cve_config
from services.cve_matching import runtime, security

log = logging.getLogger("integration.reports_api")

router = APIRouter(tags=["integration"])


# --------------------------------------------------------------------------- #
# Auth (shared HS256 + role mechanism).                                        #
# --------------------------------------------------------------------------- #
async def _claims(authorization: Optional[str] = Header(default=None)) -> dict:
    if not security.auth_enabled():
        return {"sub": "dev", "role": "admin"}
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    try:
        return security.verify_token(token)
    except security.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


def require(permission: str):
    async def _dep(claims: dict = Depends(_claims)) -> dict:
        try:
            security.require_permission(claims, permission)
        except security.AuthError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return claims

    return _dep


# --------------------------------------------------------------------------- #
# Models.                                                                      #
# --------------------------------------------------------------------------- #
class JobRow(BaseModel):
    job_id: str
    status: str
    uploaded_by: str
    created_at: str
    completed_at: Optional[str] = None


class JobsResponse(BaseModel):
    jobs: List[JobRow]


# --------------------------------------------------------------------------- #
# Job lister (pg-backed, best-effort, injectable).                             #
# --------------------------------------------------------------------------- #
JobLister = Callable[[], List[dict]]
_lister: Optional[JobLister] = None


def set_jobs_lister(lister: Optional[JobLister]) -> None:
    global _lister
    _lister = lister


def get_jobs_lister() -> JobLister:
    return _lister or _pg_jobs_lister


def _pg_jobs_lister() -> List[dict]:
    """List all jobs newest-first. Best-effort: [] if psycopg/table unavailable."""
    try:
        import psycopg  # lazy
    except Exception:
        return []
    try:
        with psycopg.connect(cve_config.postgres_dsn(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT job_id, status, uploaded_by, created_at, completed_at "
                    "FROM jobs ORDER BY created_at DESC LIMIT 500;"
                )
                return [
                    {
                        "job_id": r[0],
                        "status": r[1],
                        "uploaded_by": r[2],
                        "created_at": r[3].isoformat() if r[3] else "",
                        "completed_at": r[4].isoformat() if r[4] else None,
                    }
                    for r in cur.fetchall()
                ]
    except Exception:
        log.warning("could not list jobs", exc_info=True)
        return []


# --------------------------------------------------------------------------- #
# Endpoints.                                                                   #
# --------------------------------------------------------------------------- #
@router.get("/jobs", response_model=JobsResponse)
async def list_jobs(claims: dict = Depends(require("view"))) -> JobsResponse:
    return JobsResponse(jobs=[JobRow(**row) for row in get_jobs_lister()()])


@router.get("/jobs/{job_id}/report")
async def get_report(job_id: str, claims: dict = Depends(require("view"))) -> dict:
    report = runtime.get_report_store().get(job_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"no report for job {job_id}")
    return report
