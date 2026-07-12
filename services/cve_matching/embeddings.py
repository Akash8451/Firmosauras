"""Embedding backends — MiniLM (all-MiniLM-L6-v2 -> 384-dim) with a deterministic
in-process fake for tests.

The real `MiniLmEmbedder` lazily imports `sentence_transformers` so importing this
module (and therefore the matcher/handler) never drags torch into a plain unit-test
run. Loading the model reads a locally-cached snapshot; it makes NO network call on
the query path once cached (hard-constraints.md Data Source Rules).

`HashingEmbedder` produces stable, L2-normalized 384-dim vectors from a hash of the
text with zero heavy dependencies, so tiering / corpus / handler logic is testable
without torch or the network.
"""
from __future__ import annotations

import hashlib
import math
from typing import List, Optional, Protocol, Sequence, runtime_checkable

from . import config


@runtime_checkable
class Embedder(Protocol):
    """Minimal embedding interface used across the CVE-matching core."""

    @property
    def dim(self) -> int: ...

    def encode(self, text: str) -> List[float]: ...

    def encode_batch(self, texts: Sequence[str]) -> List[List[float]]: ...


def _l2_normalize(vec: List[float]) -> List[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return vec
    return [v / norm for v in vec]


class MiniLmEmbedder:
    """Production embedder backed by sentence-transformers/all-MiniLM-L6-v2.

    Lazy-loads the model on first use; embeddings are L2-normalized so cosine
    similarity reduces to a dot product (matches pgvector `vector_cosine_ops`).
    """

    def __init__(self, model_name: Optional[str] = None, dim: Optional[int] = None) -> None:
        self.model_name = model_name or config.EMBEDDING_MODEL
        self._dim = dim or config.EMBEDDING_DIM
        self._model = None  # lazy

    @property
    def dim(self) -> int:
        return self._dim

    def _load(self):
        if self._model is None:
            # Imported lazily: keeps torch out of unit-test import paths.
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
            loaded_dim = self._model.get_sentence_embedding_dimension()
            if loaded_dim != self._dim:
                raise RuntimeError(
                    f"embedding dim mismatch: model {self.model_name} produces "
                    f"{loaded_dim}-dim but config expects {self._dim}. Model and "
                    "EMBEDDING_DIM / vector(N) must change together (SCHEMA.md §6)."
                )
        return self._model

    def encode(self, text: str) -> List[float]:
        return self.encode_batch([text])[0]

    def encode_batch(self, texts: Sequence[str]) -> List[List[float]]:
        model = self._load()
        vecs = model.encode(
            list(texts), normalize_embeddings=True, convert_to_numpy=True
        )
        return [list(map(float, v)) for v in vecs]


class HashingEmbedder:
    """Deterministic, dependency-free embedder for tests.

    Not semantically meaningful, but stable: the same text always maps to the same
    unit vector, and lexically similar strings that share tokens land nearer each
    other (token-hash bag-of-words). Enough to exercise ranking + tiering logic
    without torch or a model download.
    """

    def __init__(self, dim: Optional[int] = None) -> None:
        self._dim = dim or config.EMBEDDING_DIM

    @property
    def dim(self) -> int:
        return self._dim

    def _bucket(self, token: str) -> int:
        h = hashlib.sha256(token.encode("utf-8")).digest()
        return int.from_bytes(h[:4], "big") % self._dim

    def encode(self, text: str) -> List[float]:
        vec = [0.0] * self._dim
        tokens = [t for t in _tokenize(text)]
        if not tokens:
            # Non-zero fallback so an empty string still yields a valid unit vector.
            vec[self._bucket(text or "empty")] = 1.0
            return _l2_normalize(vec)
        for tok in tokens:
            vec[self._bucket(tok)] += 1.0
        return _l2_normalize(vec)

    def encode_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.encode(t) for t in texts]


def _tokenize(text: str) -> List[str]:
    out: List[str] = []
    cur: List[str] = []
    for ch in (text or "").lower():
        if ch.isalnum() or ch in ".-_":
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


# Process-wide default embedder. The matcher pulls from here so a caller (or a
# test) can inject a fake without threading it through every function.
_default_embedder: Optional[Embedder] = None


def get_embedder() -> Embedder:
    """Return the process default embedder (MiniLM), constructing it on first use."""
    global _default_embedder
    if _default_embedder is None:
        _default_embedder = MiniLmEmbedder()
    return _default_embedder


def set_embedder(embedder: Optional[Embedder]) -> None:
    """Override the default embedder (used by tests / the ETL harness)."""
    global _default_embedder
    _default_embedder = embedder
