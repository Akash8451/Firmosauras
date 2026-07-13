"""Process-wide singletons for the Upload Gateway.

Mirrors ``services/cve_matching/runtime.py``: lazily construct the real backends
(so a plain unit-test import pulls in no boto3 / psycopg / kafka deps) and allow
tests to inject in-memory fakes via ``set_*``.
"""
from __future__ import annotations

from typing import Optional

from .events import EventEmitter, KafkaEmitter
from .jobs import JobsRepo, PostgresJobsRepo
from .storage import S3Storage, StorageClient

__all__ = [
    "get_storage",
    "set_storage",
    "get_jobs_repo",
    "set_jobs_repo",
    "get_emitter",
    "set_emitter",
    "reset",
]

_storage: Optional[StorageClient] = None
_jobs_repo: Optional[JobsRepo] = None
_emitter: Optional[EventEmitter] = None


def get_storage() -> StorageClient:
    global _storage
    if _storage is None:
        _storage = S3Storage()
    return _storage


def set_storage(storage: Optional[StorageClient]) -> None:
    global _storage
    _storage = storage


def get_jobs_repo() -> JobsRepo:
    global _jobs_repo
    if _jobs_repo is None:
        _jobs_repo = PostgresJobsRepo()
    return _jobs_repo


def set_jobs_repo(repo: Optional[JobsRepo]) -> None:
    global _jobs_repo
    _jobs_repo = repo


def get_emitter() -> EventEmitter:
    global _emitter
    if _emitter is None:
        _emitter = KafkaEmitter()
    return _emitter


def set_emitter(emitter: Optional[EventEmitter]) -> None:
    global _emitter
    _emitter = emitter


def reset() -> None:
    """Clear all singletons (used by tests)."""
    set_storage(None)
    set_jobs_repo(None)
    set_emitter(None)
