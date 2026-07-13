# `firmware.extracted` example payloads (Group 2 → Group 3)

Additional, on-contract `firmware.extracted` samples the unpacker fans out (one
per leaf sub-blob, keyed by `sub_blob_id` — SCHEMA.md §1). The canonical one lives
at `sample_payloads/firmware.extracted.json`. These cover the lineage cases:

| File | Demonstrates |
|---|---|
| `firmware.extracted.root_child.json` | a leaf extracted directly from the uploaded blob (`parent_blob_id: null`) |
| `firmware.extracted.nested_child.json` | a leaf from a nested container (`parent_blob_id` set to its parent container) |

They live in this subdirectory (not the top level) because the `schema_lint` gate
treats each top-level file's stem as a topic and expects exactly one sample per
topic. All files here still validate against `shared/contracts/FirmwareExtracted`
— see `services/ingestion/tests/test_sample_examples.py`.

Convention (SCHEMA.md §2): `s3_key` follows `extracted/{job_id}/{sub_blob_id}.bin`.
