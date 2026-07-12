"""Kafka router: a single confluent-kafka consumer loop that dispatches each
message to the handler registered for its topic (decorator auto-registration),
with manual offset commits and poison-pill / DLQ handling.

Group 1 owns `runner.py`, `registry.py`, `context.py`, `idempotency.py`,
`dlq.py`, and `topology.py`. Handler bodies in `handlers/` are owned by Groups 2
and 3 (see CODEOWNERS); Group 1 seeds them as stubs.
"""
