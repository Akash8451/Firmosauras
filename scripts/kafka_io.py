"""Shared Kafka/Redpanda helpers for the dev harness.

Centralizes broker config, partition-key derivation, and contract validation so
`emit_test_event.py`, `consume_topic.py`, and the round-trip test all behave
identically and stay on-contract.

Partition keying follows SCHEMA.md §1 (enforced here so the harness models real
producer behavior):
  * job-scoped topics  -> keyed by `job_id`
  * fan-out topics      -> keyed by `sub_blob_id`
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any, Dict, Optional

# Make `shared` importable whether run as `python scripts/x.py` or `-m scripts.x`.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from shared.contracts import validate_payload  # noqa: E402,F401  (re-exported)
from shared.topics import partition_key  # noqa: E402


def broker() -> str:
    """Host-facing Redpanda bootstrap (natively-run scripts use the external listener)."""
    return os.getenv("REDPANDA_BROKERS", "127.0.0.1:19092")


def key_for(topic: str, payload: Dict[str, Any]) -> Optional[str]:
    """Derive the Kafka message key per SCHEMA.md §1 (delegates to shared)."""
    return partition_key(topic, payload)


def make_producer():
    from confluent_kafka import Producer

    return Producer(
        {
            "bootstrap.servers": broker(),
            "client.id": "firmosaurus-harness-producer",
            "enable.idempotence": True,
        }
    )


def make_consumer(group_id: str, from_beginning: bool = True):
    from confluent_kafka import Consumer

    return Consumer(
        {
            "bootstrap.servers": broker(),
            "group.id": group_id,
            "auto.offset.reset": "earliest" if from_beginning else "latest",
            "enable.auto.commit": True,
        }
    )


def produce_event(
    producer, topic: str, payload: Dict[str, Any], *, validate: bool = True
) -> Optional[str]:
    """Produce one event to `topic`, keyed per the schema. Returns the key used.

    By default the payload is validated against its contract first — the harness
    never emits an off-contract message.
    """
    if validate:
        payload = validate_payload(topic, payload)
    key = key_for(topic, payload)
    producer.produce(
        topic,
        key=key.encode() if key else None,
        value=json.dumps(payload).encode(),
    )
    producer.flush(10)
    return key
