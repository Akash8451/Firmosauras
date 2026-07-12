"""CI schema-lint gate.

Imports `shared/contracts/` and validates every file in `sample_payloads/`
against its topic's model. Fails (exit 1) if any payload is off-contract, if a
sample maps to an unknown topic, or if a topic is missing a sample. This is the
CI check that turns silent schema drift into a red build.

Usage:
    python scripts/schema_lint.py
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from shared.contracts import TOPIC_MODELS, validate_payload  # noqa: E402

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SAMPLES = _REPO_ROOT / "sample_payloads"


def main() -> int:
    errors: list[str] = []
    seen_topics: set[str] = set()

    sample_files = sorted(_SAMPLES.glob("*.json"))
    if not sample_files:
        print(f"ERROR: no sample payloads found in {_SAMPLES}", file=sys.stderr)
        return 1

    for path in sample_files:
        topic = path.stem
        seen_topics.add(topic)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            validate_payload(topic, payload)
            print(f"  OK   {path.name}")
        except Exception as exc:  # json or validation failure
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            print(f"  FAIL {path.name}: {exc}")

    # Coverage: every topic in the contract registry must have a sample.
    missing = sorted(set(TOPIC_MODELS) - seen_topics)
    for topic in missing:
        errors.append(f"missing sample payload for topic {topic!r}")
        print(f"  MISSING sample_payloads/{topic}.json")

    if errors:
        print(f"\nschema-lint FAILED with {len(errors)} error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"\nschema-lint OK: {len(sample_files)} payload(s) valid, "
          f"all {len(TOPIC_MODELS)} topics covered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
