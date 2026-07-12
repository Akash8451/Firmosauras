"""Emit a sample event to Redpanda.

Usage:
    python scripts/emit_test_event.py <topic> <payload.json>

Example:
    python scripts/emit_test_event.py firmware.triaged sample_payloads/firmware.triaged.json

The payload is validated against `shared/contracts/` before being produced, and
keyed per the SCHEMA.md §1 partition rules (job_id, or sub_blob_id for fan-out
topics). An invalid payload fails loudly instead of poisoning a partition.
"""
from __future__ import annotations

import json
import pathlib
import sys

# Ensure repo root on path when run as a file.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts.kafka_io import broker, make_producer, produce_event  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2

    topic, payload_path = argv[1], argv[2]
    try:
        with open(payload_path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not read/parse {payload_path}: {exc}", file=sys.stderr)
        return 1

    producer = make_producer()
    try:
        key = produce_event(producer, topic, payload)
    except Exception as exc:  # validation or produce failure
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"Emitted to {topic} (broker={broker()}, key={key})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
