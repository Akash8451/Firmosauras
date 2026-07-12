# `firmware.matched` example payloads (Group 3 → Group 4)

Additional, on-contract `firmware.matched` samples for the frontend to build
against. The canonical one lives at `sample_payloads/firmware.matched.json`
(CONFIRMED + POSSIBLE). These cover the remaining tiers and the empty case:

| File | Demonstrates |
|---|---|
| `firmware.matched.high_confidence.json` | `HIGH_CONFIDENCE` via `embedding_similarity` (no `llm_rationale`) |
| `firmware.matched.low_confidence.json` | `LOW_CONFIDENCE` with an `llm_rationale` |
| `firmware.matched.no_findings.json` | a sub-blob with `cve_matches: []` |

They live in this subdirectory (not the top level) because the `schema_lint` gate
treats each top-level file's stem as a topic and expects exactly one sample per
topic. All files here still validate against `shared/contracts/FirmwareMatched` —
see `services/cve_matching/tests/test_sample_examples.py`.

Conventions enforced (SCHEMA.md §2):
- `NO_MATCH` entries are never present.
- `matched_via: exact_cpe` implies `similarity_score: null` and tier `CONFIRMED`.
- `llm_rationale` is populated only for `POSSIBLE` / `LOW_CONFIDENCE`.
