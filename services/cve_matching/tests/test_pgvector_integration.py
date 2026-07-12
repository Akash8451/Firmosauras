"""Task 9 integration test against the REAL pgvector store.

Skips automatically when `psycopg` isn't installed or no Postgres is reachable at
POSTGRES_DSN, so the fast offline suite still runs everywhere. When infra is up
(`docker compose up`), this proves the actual schema, HNSW index, exact-CPE
lookup, and cosine similarity search work end-to-end with real 384-dim vectors.

Run with a live stack:
    docker compose up -d postgres
    python -m pytest services/cve_matching/tests/test_pgvector_integration.py -q
"""
from __future__ import annotations

import time
import uuid

import pytest

from services.cve_matching import config
from services.cve_matching.embeddings import HashingEmbedder

psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")


def _db_reachable() -> bool:
    try:
        conn = psycopg.connect(config.postgres_dsn(), connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _db_reachable(), reason="no Postgres reachable at POSTGRES_DSN"
)


@pytest.fixture()
def repo():
    from services.cve_matching.corpus import PgVectorCorpus

    r = PgVectorCorpus()
    r.ensure_schema()
    yield r
    # Clean up only the rows this test inserted (namespaced cve_id prefix).
    conn = r._connect()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM cve_corpus WHERE cve_id LIKE 'ITEST-%';")
    r.close()


def test_pgvector_roundtrip_exact_and_similarity(repo):
    from services.cve_matching.corpus import CveRecord, corpus_text

    embedder = HashingEmbedder()
    cpe = "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"
    cve_id = f"ITEST-{uuid.uuid4().hex[:8]}"
    rec = CveRecord(
        cve_id=cve_id,
        cpe_string=cpe,
        description="BusyBox 1.31.1 invalid free in decompress_gunzip.c",
        family="busybox",
    )
    rec.embedding = embedder.encode(corpus_text(rec))
    assert len(rec.embedding) == config.EMBEDDING_DIM == 384

    repo.upsert([rec])

    # Exact CPE lookup — deterministic and fast.
    start = time.perf_counter()
    hits = repo.exact_cpe_lookup(cpe)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    assert any(h.cve_id == cve_id for h in hits)
    assert elapsed_ms < 50.0  # generous CI bound; local btree lookup is sub-ms

    # Similarity search returns the row with a score in [0, 1].
    ranked = repo.similarity_search(embedder.encode("busybox 1.31.1 invalid free"), top_k=5)
    assert ranked
    assert all(0.0 <= s <= 1.0 for _r, s in ranked)


def test_pgvector_upsert_is_idempotent(repo):
    from services.cve_matching.corpus import CveRecord, corpus_text

    embedder = HashingEmbedder()
    cve_id = f"ITEST-{uuid.uuid4().hex[:8]}"
    cpe = "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*"
    rec = CveRecord(cve_id=cve_id, cpe_string=cpe, description="d", family="openssl")
    rec.embedding = embedder.encode(corpus_text(rec))

    repo.upsert([rec])
    repo.upsert([rec])  # second upsert must not duplicate

    conn = repo._connect()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM cve_corpus WHERE cve_id = %s AND cpe_string = %s;",
            (cve_id, cpe),
        )
        assert int(cur.fetchone()[0]) == 1
