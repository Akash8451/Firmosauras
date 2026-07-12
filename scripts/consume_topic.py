"""Subscribe to a topic and print messages as they arrive.

Usage:
    python scripts/consume_topic.py <topic> [--group GROUP] [--count N]
                                            [--latest] [--timeout SECONDS]

Examples:
    python scripts/consume_topic.py firmware.analyzed
    python scripts/consume_topic.py firmware.matched --count 1 --group debug-me

By default it reads from the beginning with an ephemeral consumer group, prints
each message as pretty JSON, and runs until interrupted (Ctrl-C) or until
--count messages have been seen.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts.kafka_io import broker, make_consumer  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Consume and print messages from a topic.")
    p.add_argument("topic")
    p.add_argument("--group", default=f"debug-{uuid.uuid4().hex[:8]}",
                   help="consumer group id (default: ephemeral)")
    p.add_argument("--count", type=int, default=0,
                   help="stop after N messages (0 = run forever)")
    p.add_argument("--latest", action="store_true",
                   help="start at the end of the topic instead of the beginning")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="poll timeout in seconds")
    return p.parse_args(argv[1:])


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    consumer = make_consumer(args.group, from_beginning=not args.latest)
    consumer.subscribe([args.topic])
    print(f"Consuming {args.topic} (broker={broker()}, group={args.group}) ...",
          file=sys.stderr)

    seen = 0
    try:
        while True:
            msg = consumer.poll(args.timeout)
            if msg is None:
                continue
            if msg.error():
                print(f"ERROR: {msg.error()}", file=sys.stderr)
                continue
            key = msg.key().decode() if msg.key() else None
            try:
                value = json.loads(msg.value())
            except (ValueError, TypeError):
                value = msg.value().decode(errors="replace")
            print(json.dumps({"key": key, "value": value}, indent=2, sort_keys=True))
            seen += 1
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
