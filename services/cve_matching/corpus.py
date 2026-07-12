"""CVE corpus repository — local pgvector store + an in-memory fake for tests.

Table shape is frozen in SCHEMA.md §6:

    cve_corpus (cpe_string, cve_id, description, embedding vector(384))

We add a `family` column (scoping / per-family threshold selection) — an additive
column, not a change to the frozen event contracts. The embedding column is
`vector(384)` because the locked model is all-MiniLM-L6-v2 (SCHEMA.md §6); pgvector
fixes the dimension at table creation, so model + dimension change together.

Both implementations expose the SAME interface (`CorpusRepository`):
  * `exact_cpe_lookup(cpe_string)`   — deterministic, the primary match path.
  * `similarity_search(embedding, k)`— cosine-similarity fallback (HNSW in pg).

Neither method makes any network call — this is the air-gapped query path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Protocol, Sequence, Tuple

from . import config, cpe as cpe_mod


@dataclass
class CveRecord:
    """One (cve_id, cpe_string) row of the corpus."""

    cve_id: str
    cpe_string: str
    description: str
    family: Optional[str] = None
    embedding: Optional[List[float]] = field(default=None, repr=False)

    def key(self) -> Tuple[str, str]:
        return (self.cve_id, self.cpe_string)


def corpus_text(record: CveRecord) -> str:
    """Text embedded for a corpus row: component identity + description.

    Prefixing the vendor/product/version makes the stored vector sit near a query
    built from a messy extracted version string, not just near the prose.
    """
    parts = cpe_mod.parse_cpe(record.cpe_string)
    if parts is not None:
        ident = f"{parts.vendor} {parts.product} {parts.version}".strip()
    else:
        ident = ""
    desc = record.description or ""
    return f"{ident}: {desc}".strip(": ").strip() or record.cve_id


class CorpusRepository(Protocol):
    """Interface shared by the real pgvector store and the in-memory test fake."""

    def ensure_schema(self) -> None: ...

    def upsert(self, records: Sequence[CveRecord]) -> int: ...

    def exact_cpe_lookup(self, cpe_string: str) -> List[CveRecord]: ...

    def similarity_search(
        self, embedding: Sequence[float], top_k: int = 5
    ) -> List[Tuple[CveRecord, float]]: ...

    def count(self) -> int: ...


# --------------------------------------------------------------------------- #
# In-memory fake — used by unit tests. Pure Python cosine similarity.          #
# --------------------------------------------------------------------------- #
class InMemoryCorpus:
    """Dict-backed corpus with the same surface as the pgvector store.

    Cosine similarity computed in Python (numpy if present, else stdlib). Keeps
    tiering/matcher/ETL tests entirely offline and dependency-free.
    """

    def __init__(self) -> None:
        self._rows: dict[Tuple[str, str], CveRecord] = {}

    def ensure_schema(self) -> None:  # no-op for the fake
        return None

    def upsert(self, records: Sequence[CveRecord]) -> int:
        for rec in records:
            self._rows[rec.key()] = rec
        return len(records)

    def exact_cpe_lookup(self, cpe_string: str) -> List[CveRecord]:
        needle = (cpe_string or "").strip().lower()
        return [r for r in self._rows.values() if r.cpe_string.lower() == needle]

    def similarity_search(
        self, embedding: Sequence[float], top_k: int = 5
    ) -> List[Tuple[CveRecord, float]]:
        q = list(embedding)
        scored: List[Tuple[CveRecord, float]] = []
        for rec in self._rows.values():
            if not rec.embedding:
                continue
            scored.append((rec, _cosine(q, rec.embedding)))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[: max(0, top_k)]

    def count(self) -> int:
        return len(self._rows)


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity clamped to [0, 1] (negatives -> 0 for tiering)."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for i in range(n):
        dot += a[i] * b[i]
        na += a[i] * a[i]
        nb += b[i] * b[i]
    if na == 0.0 or nb == 0.0:
        return 0.0
    sim = dot / (na ** 0.5 * nb ** 0.5)
    if sim < 0.0:
        return 0.0
    if sim > 1.0:
        return 1.0
    return sim


# --------------------------------------------------------------------------- #
# Real pgvector-backed store.                                                  #
# --------------------------------------------------------------------------- #
class PgVectorCorpus:
    """Postgres + pgvector implementation of `CorpusRepository`.

    Lazy-imports `psycopg` so a plain unit-test run never needs the driver. Uses
    cosine distance (`<=>` with `vector_cosine_ops`) and an HNSW index; the
    returned similarity is `1 - cosine_distance`, clamped to [0, 1].
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or config.postgres_dsn()
        self._conn = None  # lazy

    # -- connection ---------------------------------------------------------- #
    def _connect(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            import psycopg  # lazy

            self._conn = psycopg.connect(self.dsn, autocommit=True)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    @staticmethod
    def _vec_literal(embedding: Sequence[float]) -> str:
        # pgvector accepts a bracketed, comma-separated string literal.
        return "[" + ",".join(repr(float(x)) for x in embedding) + "]"

    # -- schema -------------------------------------------------------------- #
    def ensure_schema(self) -> None:
        dim = config.EMBEDDING_DIM
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS cve_corpus (
                    cve_id       TEXT        NOT NULL,
                    cpe_string   TEXT        NOT NULL,
                    description  TEXT        NOT NULL DEFAULT '',
                    family       TEXT,
                    embedding    vector({dim}) NOT NULL,
                    PRIMARY KEY (cve_id, cpe_string)
                );
                """
            )
            # Deterministic exact-CPE lookups hit this btree index.
            cur.execute(
                "CREATE INDEX IF NOT EXISTS cve_corpus_cpe_idx "
                "ON cve_corpus (cpe_string);"
            )
            # HNSW index for cosine-similarity fallback search.
            cur.execute(
                "CREATE INDEX IF NOT EXISTS cve_corpus_embedding_hnsw "
                "ON cve_corpus USING hnsw (embedding vector_cosine_ops);"
            )

    # -- writes -------------------------------------------------------------- #
    def upsert(self, records: Sequence[CveRecord]) -> int:
        if not records:
            return 0
        conn = self._connect()
        with conn.cursor() as cur:
            for rec in records:
                if not rec.embedding:
                    raise ValueError(
                        f"record {rec.cve_id}/{rec.cpe_string} has no embedding; "
                        "the ETL must embed before upsert"
                    )
                cur.execute(
                    """
                    INSERT INTO cve_corpus (cve_id, cpe_string, description, family, embedding)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id, cpe_string) DO UPDATE
                      SET description = EXCLUDED.description,
                          family      = EXCLUDED.family,
                          embedding   = EXCLUDED.embedding;
                    """,
                    (
                        rec.cve_id,
                        rec.cpe_string,
                        rec.description,
                        rec.family,
                        self._vec_literal(rec.embedding),
                    ),
                )
        return len(records)

    # -- reads (query path: NO network) ------------------------------------- #
    def exact_cpe_lookup(self, cpe_string: str) -> List[CveRecord]:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cve_id, cpe_string, description, family "
                "FROM cve_corpus WHERE cpe_string = %s;",
                (cpe_string,),
            )
            return [
                CveRecord(cve_id=r[0], cpe_string=r[1], description=r[2], family=r[3])
                for r in cur.fetchall()
            ]

    def similarity_search(
        self, embedding: Sequence[float], top_k: int = 5
    ) -> List[Tuple[CveRecord, float]]:
        conn = self._connect()
        vec = self._vec_literal(embedding)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cve_id, cpe_string, description, family,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM cve_corpus
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
                """,
                (vec, vec, top_k),
            )
            out: List[Tuple[CveRecord, float]] = []
            for r in cur.fetchall():
                sim = float(r[4])
                sim = 0.0 if sim < 0.0 else (1.0 if sim > 1.0 else sim)
                out.append(
                    (
                        CveRecord(cve_id=r[0], cpe_string=r[1], description=r[2], family=r[3]),
                        sim,
                    )
                )
            return out

    def count(self) -> int:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cve_corpus;")
            return int(cur.fetchone()[0])
