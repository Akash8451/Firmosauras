"""Kafka consumer for the notifier — its OWN consumer group.

Subscribes to every `firmware.*` topic and invokes a callback `(topic, payload)`
for each decoded message. It uses a DISTINCT `group.id` (`firmosaurus-notifier`)
so it receives its own copy of the stream independently of the router's consumer
group (backend-architecture.md rule 5). The poll loop is injectable/overridable so
the progress logic can be tested without a live broker.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Callable

from shared import topics

log = logging.getLogger("notifier.consumer")

NOTIFIER_GROUP = "firmosaurus-notifier"

EventCallback = Callable[[str, dict], None]


class NotifierConsumer:
    def __init__(self, *, group_id: str = NOTIFIER_GROUP, broker: str | None = None) -> None:
        self.group_id = group_id
        self.broker = broker or os.getenv("REDPANDA_BROKERS", "127.0.0.1:19092")
        self._consumer = None
        self._stop = False

    def _make_consumer(self):
        from confluent_kafka import Consumer

        return Consumer(
            {
                "bootstrap.servers": self.broker,
                "group.id": self.group_id,
                "enable.auto.commit": True,   # progress is best-effort; no exactly-once needed
                "auto.offset.reset": "latest",  # only care about live progress
            }
        )

    def stop(self) -> None:
        self._stop = True

    def run(self, on_event: EventCallback) -> None:  # pragma: no cover (needs a broker)
        from confluent_kafka import KafkaError

        self._consumer = self._make_consumer()
        self._consumer.subscribe(list(topics.ALL_TOPICS))
        log.info("notifier consumer up: group=%s broker=%s", self.group_id, self.broker)
        try:
            while not self._stop:
                msg = self._consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.error("notifier consumer error: %s", msg.error())
                    continue
                try:
                    payload = json.loads(msg.value())
                    on_event(msg.topic(), payload)
                except Exception:
                    log.warning("notifier failed to handle message on %s", msg.topic(), exc_info=True)
        finally:
            self._consumer.close()
