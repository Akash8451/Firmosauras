---
inclusion: always
---
# SCHEMA.md — Canonical Data Shapes & Naming Reference

This file is the single source of truth for event payloads, Redis key names, and stored document shapes. Any handler, migration, or agent-generated code MUST match these names exactly — do not introduce variant spellings (e.g. `children_total` vs `total_children`) across sessions.

---

## 1. Kafka Topics (in pipeline order)

```
firmware.uploaded
firmware.triaged
firmware.extracted
firmware.analyzed
firmware.matched
firmware.completed
firmware.dlq
```

**Partition keying (REQUIRED):**
- `firmware.uploaded`, `firmware.triaged`, `firmware.completed`, `firmware.dlq` → keyed by `job_id` (one message per job; per-job ordering is fine here).
- **Fan-out topics `firmware.extracted`, `firmware.analyzed`, `firmware.matched` → keyed by `sub_blob_id` (the child id), NOT `job_id`.** Keying these by `job_id` pins all of a job's sub-blobs onto one partition and destroys the horizontally-scaled analysis parallelism that is the entire point of the fan-out.
- Completion is tracked via the Redis counters (`total_children` / `matched_children`) + the `extraction_complete` marker — NEVER via Kafka ordering. Per-job ordering on the fan-out topics is intentionally not required.

## 2. Kafka Event Payload Shapes

### `firmware.uploaded`
```json
{
  "job_id": "uuid",
  "s3_key": "raw-uploads/{job_id}/original.bin",
  "uploaded_by": "user_id",
  "uploaded_at": "iso8601"
}
```

### `firmware.triaged`
```json
{
  "job_id": "uuid",
  "sha256": "hex string",
  "is_duplicate": false,
  "size_bytes": 12345678
}
```

### `firmware.extracted` (one event per sub-blob — fan-out)
```json
{
  "job_id": "uuid",
  "sub_blob_id": "uuid",
  "s3_key": "extracted/{job_id}/{sub_blob_id}.bin",
  "parent_blob_id": "uuid | null"
}
```

### `firmware.analyzed`
```json
{
  "job_id": "uuid",
  "sub_blob_id": "uuid",
  "strings_found": ["..."],
  "entropy_sections": [{"offset": 0, "entropy": 7.8, "flagged_packed": true}],
  "version_candidates": [{"vendor": "busybox", "product": "busybox", "version": "1.31.1"}],
  "secrets_flagged": [{"type": "private_key_header", "context": "..."}],
  "hardening_flags": {"nx": true, "pie": false, "relro": "partial", "canary": true}
}
```

### `firmware.matched`
```json
{
  "job_id": "uuid",
  "sub_blob_id": "uuid",
  "cve_matches": [
    {
      "cve_id": "CVE-2021-XXXXX",
      "confidence_tier": "CONFIRMED | HIGH_CONFIDENCE | POSSIBLE | LOW_CONFIDENCE | NO_MATCH",
      "similarity_score": 0.92,
      "matched_via": "exact_cpe | embedding_similarity",
      "llm_rationale": "string | null"
    }
  ]
}
```

**Confidence tiering (LOCKED initial thresholds — used by the CVE-match stage):**

| Tier | Condition |
|---|---|
| `CONFIRMED` | exact CPE match (`matched_via = exact_cpe`) |
| `HIGH_CONFIDENCE` | `similarity_score >= 0.90` |
| `POSSIBLE` | `0.70 <= similarity_score < 0.90` |
| `LOW_CONFIDENCE` | `0.50 <= similarity_score < 0.70` |
| `NO_MATCH` | `similarity_score < 0.50` |

These are the INITIAL thresholds. The feedback loop (Task 14) recalibrates them per component family, so store them as config (per-family, defaulting to the above) — do not scatter hardcoded 0.90/0.70/0.50 literals through the code.

**`firmware.matched` conventions:**
- For `matched_via = exact_cpe`, set `similarity_score: null` (exact matches have no similarity score).
- Do NOT emit `NO_MATCH` entries in `cve_matches[]` — only `CONFIRMED`…`LOW_CONFIDENCE` appear. A sub-blob with no findings emits `cve_matches: []`.
- `llm_rationale` is populated ONLY for `POSSIBLE`/`LOW_CONFIDENCE`; it is `null` for `CONFIRMED` (and `NO_MATCH` isn't emitted at all).

### `firmware.completed`
```json
{
  "job_id": "uuid",
  "status": "COMPLETE",
  "report_s3_key": "reports/{job_id}/report.json",
  "sbom_s3_key": "reports/{job_id}/sbom.json"
}
```

### `firmware.dlq`
```json
{
  "original_topic": "string",
  "payload": "raw original message bytes/string",
  "error": "string",
  "failed_at": "iso8601"
}
```

---

## 3. Redis Key Naming Conventions

| Purpose | Key Pattern | Type |
|---|---|---|
| Bloom filter (dedup) | `bloom:firmware_hashes` | Redis bitmap (hand-rolled Bloom) |
| Fan-out total children | `job:{job_id}:total_children` | Integer counter |
| Fan-out completed children (analysis stage) | `job:{job_id}:completed_children` | Integer counter |
| Fan-out matched children (CVE-match stage) | `job:{job_id}:matched_children` | Integer counter |
| Extraction-complete marker | `job:{job_id}:extraction_complete` | Boolean flag (0/1) |
| Distributed lock (DLQ retry claim) | `lock:dlq_retry:{job_id}` | Redlock, short TTL |
| Idempotency check (processed message) | `processed:{topic}:{message_key}` | Boolean flag, TTL-bound |

**Counter naming rule:** always use `total_children` / `completed_children` / `matched_children` (never `children_total`, `child_count`, or other variants) — this exact naming must be used in every handler.

**Counter semantics:** `completed_children` is incremented at the static-analysis stage (`firmware.analyzed`); `matched_children` is incremented at the CVE-match stage (`firmware.matched`). They are distinct — do not conflate them.

**Completion / aggregation gate:** the Report Aggregator assembles the final report only when `matched_children == total_children` AND the `extraction_complete` marker is set. Do NOT gate on `completed_children` — a child can be analyzed but not yet matched, so gating on the analysis-stage counter fires the aggregator early.

**Bloom filter rule:** `bloom:firmware_hashes` is a hand-rolled Bloom filter over a plain Redis bitmap (`SETBIT`/`GETBIT`) with `k` hash functions derived by double hashing (`bit_i = (h1 + i*h2) mod m`). **Pinned sizing:** target FPR = 1% at expected capacity `n` = 100,000 hashes → `m` ≈ 958,506 bits (~120 KB), `k` = 7. It is NOT RedisBloom — do not use the `BF.*` module. Task 6 test: (a) every inserted hash tests positive — Bloom filters have zero false negatives by construction; (b) the measured false-positive rate on a disjoint 10,000-hash set stays ≤ 2%; (c) `k` > 1 and the `k` positions are distinct bits (a single hash setting one bit is a lossy hash set, not a Bloom filter).

**Isolation rule:** all keys above live on a single `noeviction` Redis instance. All state here is structural (counters, markers, locks, idempotency), so there is no separate cache tier / cache DB to isolate from.

---

## 4. SBOM Output Shape (`sbom.json`)

```json
{
  "job_id": "uuid",
  "generated_at": "iso8601",
  "components": [
    {"vendor": "busybox", "product": "busybox", "version": "1.31.1", "source_sub_blob_id": "uuid"}
  ]
}
```

## 5. RBAC Role Claims (JWT)

```json
{
  "sub": "user_id",
  "role": "admin | analyst | reader"
}
```

| Role | Upload | Analyze | View/Triage | Submit Feedback | Manage Config |
|---|---|---|---|---|---|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `analyst` | ✅ | ✅ | ✅ | ✅ | ❌ |
| `reader` | ❌ | ❌ | ✅ (view/download only) | ❌ | ❌ |

---

## 6. Postgres Tables (core, non-exhaustive)

- `jobs (job_id PK, status, uploaded_by, created_at, completed_at)`
- `cve_corpus (cpe_string, cve_id, description, embedding vector(384))`
- `analyst_feedback (feedback_id PK, job_id, cve_id, verdict, submitted_by, submitted_at)`

**Embedding model (LOCKED — decide in Group 1 / Task 1, before Group 3 writes the migration):**
the embedding model is `sentence-transformers/all-MiniLM-L6-v2`, which produces **384-dim**
vectors. `pgvector` fixes the column dimension at table creation, so `cve_corpus.embedding`
and the per-job RAG index MUST both be `vector(384)`. If the model is ever swapped, the
dimension here and the migration change together — never change one without the other.

## 7. MongoDB Collections

- `reports` — one document per `job_id`, full assembled report (flexible schema for heterogeneous firmware structures)

---

## 8. External LLM (optional enhancement — NOT part of the air-gapped core)

The LLM is used ONLY for narration on ambiguous tiers (Task 10: `POSSIBLE`/`LOW_CONFIDENCE`
triage + exec summary) and RAG chat (Task 13). It is an **optional external enhancement** and
is deliberately kept separate from the air-gapped CVE-matching core:

- **Air-gapped core:** CVE matching runs against local `pgvector` with **no network call on
  the query path**. This is the part that must work offline.
- **LLM layer:** an external API call, downstream of the deterministic match decision. It
  explains/ranks; it never invents a finding, and it is never called on `CONFIRMED`/`NO_MATCH`.
  If the LLM is unavailable, matching still completes — the narration is simply omitted.

**Provider (LOCKED — FREE tiers only, swappable via env; decide before Group 3 hits Task 10):**
All candidates are exposed through an **OpenAI-compatible** client (base URL + model + key), so
switching providers is config-only — no schema or handler-contract change.

- **Default — Groq, `llama-3.3-70b-versatile`.** Permanent free tier, no credit card, very fast;
  70B quality is strong for grounded triage/summary + RAG. Free limits are low volume
  (~30 RPM / 1,000 RPD), which is fine because triage fires only on `POSSIBLE`/`LOW_CONFIDENCE`
  and RAG sends only retrieved chunks.
- **Failover — Google Gemini, `gemini-2.5-flash-lite`.** Free tier ~15 RPM / 1,000 RPD, 1M-token
  context (useful for whole-report prompts). Has an OpenAI-compat endpoint.

- Config via environment only — never hardcode or commit keys:
  - `LLM_PROVIDER=groq`
  - `LLM_MODEL=llama-3.3-70b-versatile`
  - `LLM_BASE_URL=https://api.groq.com/openai/v1`
  - `LLM_API_KEY=...`  ← lives in `.env` (gitignored); `.env.example` ships the key names with empty values.
- Privacy note: free cloud tiers may train on inputs. The LLM only ever sees match rationales /
  report text (component versions, CVE descriptions), never the raw firmware blob.

---

**Update rule:** any new field, topic, or key introduced during development must be added here in the same commit. Do not let this file go stale — an agent (or you, three weeks from now) should never have to guess a field name.
