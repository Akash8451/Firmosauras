"""Event emitter — the gateway's ONLY producer (``firmware.uploaded``).

The gateway runs as its own process (not the router), so it owns a small producer
rather than a ``ctx.emit``. It still obeys the same discipline as the router
(``services/router/runner.py``):

  * validate the payload OUT against ``shared.contracts`` before producing, so a
    drifted payload is a loud error here rather than a mystery downstream;
  * key the message per ``shared.topics.partition_key`` (``firmware.uploaded`` is
    job-keyed).

The real backend is lazy-imported ``confluent-kafka``; the in-memory fake records
emitted events so tests can assert we emit exactly once, and only after the S3
completion callback.
"""
from __future__ import annotations

import json
import logging
import os
from typing import List, Protocol, Tuple

from shared.contracts import validate_payload
from shared.topics import partition_key

log = logging.getLogger("gateway.events")


class EventEmitter(Protocol):
    def emit(self, topic: str, payload: dict) -> None: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests).                                                      #
# --------------------------------------------------------------------------- #
class InMemoryEmitter:
    def __init__(self) -> None:
        self.emitted: List[Tuple[str, dict]] = []

    def emit(self, topic: str, payload: dict) -> None:
        # Validate OUT exactly like the real emitter so tests catch drift too.
        validated = validate_payload(topic, payload)
        self.emitted.append((topic, validated))


# --------------------------------------------------------------------------- #
# Kafka/Redpanda-backed emitter.                                              #
# --------------------------------------------------------------------------- #
class KafkaEmitter:
    def __init__(self, *, brokers: str | None = None) -> None:
        self.brokers = brokers or os.getenv("REDPANDA_BROKERS", "127.0.0.1:19092")
        self._producer = None

    def _get_producer(self):
        if self._producer is None:
            from confluent_kafka import Producer  # lazy

            self._producer = Producer(
                {
                    "bootstrap.servers": self.brokers,
                    "client.id": "firmosaurus-gateway-producer",
                    "enable.idempotence": True,
                }
            )
        return self._producer

    def emit(self, topic: str, payload: dict) -> None:
        validated = validate_payload(topic, payload)  # validate OUT
        key = partition_key(topic, validated)
        producer = self._get_producer()
        producer.produce(
            topic,
            key=key.encode() if key else None,
            value=json.dumps(validated).encode(),
        )
        producer.flush(10)
        log.info("emitted %s key=%s", topic, key)
