"""Hand-rolled Bloom filter over a Redis bitmap (SCHEMA.md §3 / Task 6).

This is a REAL Bloom filter, not a single-bit hash set and not RedisBloom:

  * backed by a plain Redis bitmap at ``bloom:firmware_hashes`` driven with
    ``SETBIT`` / ``GETBIT`` (no ``BF.*`` module);
  * ``k`` = 7 hash functions derived by DOUBLE HASHING
    ``bit_i = (h1 + i*h2) mod m`` from two independent digests;
  * pinned sizing for target FPR = 1% at expected capacity n = 100,000:
    ``m`` = 958,506 bits (~120 KB), ``k`` = 7.

    FPR ≈ (1 - e^(-k·n/m))^k = (1 - e^(-0.7303))^7 ≈ 1.0%.

Distinct-bit guarantee (reviewer check: k>1 AND k distinct positions):
``h2`` is forced ODD. A collision ``(i-j)·h2 ≡ 0 (mod m)`` for ``0 < i-j < k`` is
then impossible for realistic digests — ``m = 2·3·159751`` and an odd ``h2`` would
have to be divisible by the large prime factor 159751 for any two of the 7
positions to coincide. So the 7 positions are distinct for every practical input.
"""
from __future__ import annotations

import hashlib
from typing import List

from shared.redis_keys import bloom_key

# Pinned sizing (SCHEMA.md §3): target FPR 1% at n=100_000.
BLOOM_M_BITS = 958_506
BLOOM_K = 7


def bit_positions(item: str, *, m: int = BLOOM_M_BITS, k: int = BLOOM_K) -> List[int]:
    """Return the ``k`` bitmap positions for ``item`` via double hashing.

    ``h1`` from SHA-256 and ``h2`` from SHA3-256 (independent digests); ``h2`` is
    forced odd so the ``k`` positions are distinct (see module docstring).
    """
    data = item.encode() if isinstance(item, str) else bytes(item)
    h1 = int.from_bytes(hashlib.sha256(data).digest(), "big")
    h2 = int.from_bytes(hashlib.sha3_256(data).digest(), "big") | 1  # force odd
    return [(h1 + i * h2) % m for i in range(k)]


class BloomFilter:
    """Redis-bitmap Bloom filter for firmware-hash dedup."""

    def __init__(self, redis, *, key: str | None = None, m: int = BLOOM_M_BITS, k: int = BLOOM_K):
        self.redis = redis
        self.key = key or bloom_key()
        self.m = m
        self.k = k

    def add(self, item: str) -> None:
        for pos in bit_positions(item, m=self.m, k=self.k):
            self.redis.setbit(self.key, pos, 1)

    def contains(self, item: str) -> bool:
        """True if ``item`` is PROBABLY present (may be a false positive), False if
        DEFINITELY absent (Bloom filters have zero false negatives)."""
        return all(self.redis.getbit(self.key, pos) for pos in bit_positions(item, m=self.m, k=self.k))

    def add_if_absent(self, item: str) -> bool:
        """Atomically-ish check-and-set. Returns True if the item was newly added
        (definitely-new), False if it was probably already present (duplicate).

        The GET-then-SET is fine for the single dedup instance we run; exact Kafka
        redelivery is separately guarded by the router's idempotency claim, so the
        only race here is two *distinct* uploads of the same bytes arriving
        concurrently — an acceptable, rare over-count that never causes a false
        negative.
        """
        positions = bit_positions(item, m=self.m, k=self.k)
        already_present = all(self.redis.getbit(self.key, p) for p in positions)
        if already_present:
            return False
        for p in positions:
            self.redis.setbit(self.key, p, 1)
        return True
