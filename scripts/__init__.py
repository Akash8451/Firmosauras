"""Group 1-owned test/dev harness.

`emit_test_event.py` / `consume_topic.py` are the pair that make "Group 2 and
Group 3 don't need each other running" true in practice: each group develops
against `sample_payloads/` by emitting and consuming on Redpanda directly.
"""
