# `firmware.analyzed` example payloads (Group 2 → Group 3)

Additional, on-contract `firmware.analyzed` samples the static-analysis stage
emits. The canonical one lives at `sample_payloads/firmware.analyzed.json`. These
cover the two ends of the spectrum:

| File | Demonstrates |
|---|---|
| `firmware.analyzed.packed_secrets.json` | fully populated: multiple version candidates, flagged secrets (private key + hardcoded credential), packed high-entropy sections, `relro: full` hardening |
| `firmware.analyzed.no_findings.json` | a benign config-like leaf: no versions, no secrets, low entropy, all-off hardening |

They live in this subdirectory (not the top level) because the `schema_lint` gate
treats each top-level file's stem as a topic and expects exactly one sample per
topic. All files here still validate against `shared/contracts/FirmwareAnalyzed`
— see `services/static_analysis/tests/test_sample_examples.py`.

Conventions (SCHEMA.md §2): `secrets_flagged` is a regex pass over the SAME
`strings_found` (not a separate pipeline); `hardening_flags.relro` is the tri-state
`none` / `partial` / `full`; `entropy` is bits/byte in `[0, 8]`.
