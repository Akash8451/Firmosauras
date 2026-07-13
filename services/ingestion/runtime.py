"""Process-wide singletons for the ingestion handlers (triage / unpack / analysis).

Mirrors ``services/cve_matching/runtime.py``: the blob store is built lazily (so a
plain unit-test import pulls in no boto3/MinIO deps) and is overridable via
``set_blobstore`` so tests inject the in-memory fake. Redis comes from the
handler's ``ctx.redis`` (the router owns it), so it is NOT a singleton here.
"""
from __future__ import annotations

from typing import Optional

from .blobstore import BlobStore, MinioBlobStore
from .extract import CompositeExtractor, Extractor

__all__ = [
    "get_blobstore",
    "set_blobstore",
    "get_extractor",
    "set_extractor",
    "reset",
]

_blobstore: Optional[BlobStore] = None
_extractor: Optional[Extractor] = None


def get_blobstore() -> BlobStore:
    global _blobstore
    if _blobstore is None:
        _blobstore = MinioBlobStore()
    return _blobstore


def set_blobstore(store: Optional[BlobStore]) -> None:
    global _blobstore
    _blobstore = store


def get_extractor() -> Extractor:
    global _extractor
    if _extractor is None:
        _extractor = CompositeExtractor()
    return _extractor


def set_extractor(extractor: Optional[Extractor]) -> None:
    global _extractor
    _extractor = extractor


def reset() -> None:
    set_blobstore(None)
    set_extractor(None)
