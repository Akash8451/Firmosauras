"""Redis check-and-set idempotency helper.

Kafka is at-least-once: a message can be redelivered (e.g. after a rebalance or a
crash between handling and commit). Before doing side-effectful work, a handler
claims `processed:{topic}:{message_key}` with SET NX. If the claim fails, the
message was already processed and is skipped — so a redelivery never
double-increments a completion counter.
"""
from __future__ import annotations

from shared.redis_keys import idempotency_key

# Default TTL for the processed-marker. Long enough to cover redelivery windows,
# bounded so the keyspace doesn't grow without limit.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def claim_message(redis_client, topic: str, message_key: str, ttl: int = DEFAULT_TTL_SECONDS) -> bool:
    """Atomically claim a message for processing.

    Returns True if this call newly claimed it (caller SHOULD process), or False
    if it was already claimed (caller should skip). Implemented as a single
    atomic `SET key 1 NX EX ttl`.
    """
    key = idempotency_key(topic, message_key)
    # redis-py returns True when the key was set, None when NX failed.
    was_set = redis_client.set(key, "1", nx=True, ex=ttl)
    return bool(was_set)
