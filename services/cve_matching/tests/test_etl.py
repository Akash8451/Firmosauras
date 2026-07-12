"""Task 9 tests — CVE corpus ETL + refresh, all offline (InMemoryCorpus + HashingEmbedder).

Covers the task's acceptance criteria that don't require a live Postgres:
  * scoping (out-of-scope CPEs never enter the corpus)
  * a known BusyBox CPE resolves from the local corpus fast (<10ms)
  * incremental refresh ingests a new record and it becomes queryable
  * NO outbound network call on the query path
The pgvector-backed store is exercised in test_pgvector_integration.py (skips
when no DB is reachable).
"""
from __future__ import annotations

import json
import pathlib
import time
from datetime import datetime, timezone

import pytest

from services.cve_matching import nvd_etl
from services.cve_matching.corpus import InMemoryCorpus
from services.cve_matching.embeddings import HashingEmbedder

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_sample.json"

BUSYBOX_CPE = "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"


@pytest.fixture()
def nvd_page() -> dict:
    with open(_FIXTURE, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture()
def populated_corpus(nvd_page):
    repo = InMemoryCorpus()
    embedder = HashingEmbedder()
    # Injected fetcher returns the fixture once, then an empty page (pagination end).
    pages = [nvd_page, {"vulnerabilities": [], "totalResults": nvd_page["totalResults"]}]

    def fake_fetch(params):
        return pages.pop(0) if pages else {"vulnerabilities": []}

    nvd_etl.run_full_etl(repo, embedder=embedder, fetch=fake_fetch)
    return repo


def test_etl_scopes_to_component_families(populated_corpus):
    # 3 in-scope CPEs (2 busybox + 1 openssl); the Windows CVE is dropped.
    assert populated_corpus.count() == 3
    families = {r.family for r in populated_corpus._rows.values()}
    assert families == {"busybox", "openssl"}
    # Out-of-scope product never entered the corpus.
    for rec in populated_corpus._rows.values():
        assert "microsoft" not in rec.cpe_string


def test_known_busybox_cpe_resolves_fast(populated_corpus):
    start = time.perf_counter()
    hits = populated_corpus.exact_cpe_lookup(BUSYBOX_CPE)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert len(hits) == 1
    assert hits[0].cve_id == "CVE-2021-28831"
    assert hits[0].family == "busybox"
    # Local lookup must be fast (task: <10ms). In-memory is comfortably under.
    assert elapsed_ms < 10.0, f"exact CPE lookup took {elapsed_ms:.3f}ms (>10ms)"


def test_incremental_refresh_ingests_new_record(populated_corpus):
    embedder = HashingEmbedder()
    new_cpe = "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
    # Not present before refresh.
    assert populated_corpus.exact_cpe_lookup(new_cpe) == []

    incremental_page = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2022-3602",
                    "descriptions": [
                        {"lang": "en", "value": "OpenSSL 3.0 X.509 email address buffer overflow."}
                    ],
                    "configurations": [
                        {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": new_cpe}]}]}
                    ],
                }
            }
        ],
    }
    pages = [incremental_page, {"vulnerabilities": []}]

    def fake_fetch(params):
        # Incremental fetch must pass the lastModStartDate window param.
        assert "lastModStartDate" in params
        return pages.pop(0) if pages else {"vulnerabilities": []}

    result = nvd_etl.run_incremental_refresh(
        populated_corpus,
        since=datetime(2022, 11, 1, tzinfo=timezone.utc),
        embedder=embedder,
        fetch=fake_fetch,
    )
    assert result.records_upserted == 1

    hits = populated_corpus.exact_cpe_lookup(new_cpe)
    assert len(hits) == 1
    assert hits[0].cve_id == "CVE-2022-3602"


def test_refresh_is_idempotent(populated_corpus, nvd_page):
    """Re-running the ingest over the same data must not duplicate rows."""
    before = populated_corpus.count()
    embedder = HashingEmbedder()
    pages = [nvd_page, {"vulnerabilities": []}]

    def fake_fetch(params):
        return pages.pop(0) if pages else {"vulnerabilities": []}

    nvd_etl.run_incremental_refresh(
        populated_corpus,
        since=datetime(2000, 1, 1, tzinfo=timezone.utc),
        embedder=embedder,
        fetch=fake_fetch,
    )
    assert populated_corpus.count() == before  # upsert, not append


def test_no_network_on_query_path(populated_corpus, monkeypatch):
    """The runtime query path (exact lookup + similarity search + embedding) must
    make NO outbound network call. We poison the network primitives and assert the
    query path still works."""
    import socket

    def _boom(*args, **kwargs):
        raise AssertionError("query path attempted a network call")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr("urllib.request.urlopen", _boom)
    # Also poison the ETL fetcher to be certain it isn't reached on the query path.
    monkeypatch.setattr(nvd_etl, "fetch_nvd_page", _boom)

    embedder = HashingEmbedder()
    # Exact lookup — deterministic, local.
    hits = populated_corpus.exact_cpe_lookup(BUSYBOX_CPE)
    assert hits and hits[0].cve_id == "CVE-2021-28831"

    # Similarity fallback — embed locally, search the local index.
    query_vec = embedder.encode("busybox 1.31.1 invalid free decompress")
    ranked = populated_corpus.similarity_search(query_vec, top_k=3)
    assert ranked, "similarity search returned nothing"
    # Every returned score is a valid similarity in [0, 1].
    for _rec, score in ranked:
        assert 0.0 <= score <= 1.0


def test_similarity_search_ranks_related_higher(populated_corpus):
    embedder = HashingEmbedder()
    # A query that shares busybox tokens should rank a busybox record on top.
    query = embedder.encode("busybox 1.31.1 decompress_gunzip invalid free huft_build")
    ranked = populated_corpus.similarity_search(query, top_k=3)
    assert ranked
    top_rec, top_score = ranked[0]
    assert top_rec.family == "busybox"
    assert top_score > 0.0
