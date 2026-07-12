"""Process-wide singletons for the CVE-match / aggregate handlers.

Handlers run inside the fat-container router and need a corpus repository, an
embedder, an LLM narrator, and a MinIO artifact store. These are constructed
lazily (so a plain unit-test import pulls in no heavy deps) and are overridable
via `set_*` so tests can inject in-memory fakes.
"""
from __future__ import annotations

from typing import Optional

from .artifacts import ArtifactStore, MinioArtifactStore
from .corpus import CorpusRepository, PgVectorCorpus
from .embeddings import Embedder, get_embedder, set_embedder  # re-exported
from .feedback import FeedbackStore, PostgresFeedbackStore
from .llm import LlmNarrator, get_narrator, set_narrator  # re-exported
from .reports import MongoReportStore, ReportStore

__all__ = [
    "get_repo",
    "set_repo",
    "get_artifact_store",
    "set_artifact_store",
    "get_report_store",
    "set_report_store",
    "get_feedback_store",
    "set_feedback_store",
    "get_embedder",
    "set_embedder",
    "get_narrator",
    "set_narrator",
]

_repo: Optional[CorpusRepository] = None
_artifact_store: Optional[ArtifactStore] = None
_report_store: Optional[ReportStore] = None
_feedback_store: Optional[FeedbackStore] = None


def get_repo() -> CorpusRepository:
    global _repo
    if _repo is None:
        _repo = PgVectorCorpus()
    return _repo


def set_repo(repo: Optional[CorpusRepository]) -> None:
    global _repo
    _repo = repo


def get_artifact_store() -> ArtifactStore:
    global _artifact_store
    if _artifact_store is None:
        _artifact_store = MinioArtifactStore()
    return _artifact_store


def set_artifact_store(store: Optional[ArtifactStore]) -> None:
    global _artifact_store
    _artifact_store = store


def get_report_store() -> ReportStore:
    global _report_store
    if _report_store is None:
        _report_store = MongoReportStore()
    return _report_store


def set_report_store(store: Optional[ReportStore]) -> None:
    global _report_store
    _report_store = store


def get_feedback_store() -> FeedbackStore:
    global _feedback_store
    if _feedback_store is None:
        _feedback_store = PostgresFeedbackStore()
    return _feedback_store


def set_feedback_store(store: Optional[FeedbackStore]) -> None:
    global _feedback_store
    _feedback_store = store
