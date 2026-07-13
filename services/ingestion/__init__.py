"""Group 2 ingestion/extraction logic (Tasks 6 & 7).

The router handlers ``triage.py`` and ``unpack.py`` are deliberately thin I/O
wrappers (mirroring how Group 3 keeps its logic in ``services/cve_matching/`` and
its handlers thin). The real work — SHA256 + Bloom dedup + magic/size pre-checks
(triage) and sandboxed, zip-bomb-hardened extraction (unpack) — lives here as
pure, unit-testable modules with in-memory fakes for their external clients.
"""
