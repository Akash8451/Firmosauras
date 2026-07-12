---
inclusion: fileMatch
fileMatchPattern: "services/{gateway,static_analysis,cve_matching}/**"
---
# Analysis Modules & RBAC Rules

## Additional Analysis Modules (low-complexity, reuse existing data — do not over-engineer)
- **Secret/key detection:** a second regex pass over the ALREADY-extracted strings from the static analysis stage (private key headers, hardcoded credential patterns). Do NOT build a separate extraction pipeline for this — it reuses the existing string-extraction output.
- **Binary hardening flags:** one additional analysis step per binary checking `NX`, `PIE`, `RELRO`, and stack canary flags (via `checksec` or direct ELF header parsing). Emit as a small structured object (e.g. `{"nx": true, "pie": false, "relro": "partial", "canary": true}`) appended to the `firmware.analyzed` event payload. Do NOT create a new Kafka topic for this.
- **SBOM output:** persist the already-resolved `(vendor, product, version)` tuples (used internally for CVE matching) as a structured `sbom.json` artifact alongside the final report in S3/MinIO. This is a new OUTPUT ARTIFACT, not new computation — do not re-derive this data separately.
- **Explicitly OUT OF SCOPE** — do not implement unless told otherwise: SSL certificate analysis, binary disassembly/decompilation.

## RBAC Tiers
Implement three JWT role tiers, not a flat admin/user split:
- `admin` — upload, analyze, manage system configuration (CVE refresh schedule, confidence-tier thresholds)
- `analyst` — upload, analyze, view/triage results, submit match-confidence feedback
- `reader` — view/download completed reports only; no upload or triage capability

Implement this as standard, self-contained JWT auth — do NOT reference or assume any external/prior project. Tokens are HS256-signed and carry a `role` claim (`admin`/`analyst`/`reader`) per SCHEMA.md §5. Validate the signature and role claim at the Upload Gateway edge, and enforce the permission table above at the API layer. Use one auth mechanism across all services — do not introduce a second.

## AI/Matching Principle (applies specifically inside cve_matching/)
Every AI call in this system is downstream of a deterministic decision, never upstream of one. The LLM explains or ranks; it never invents a vulnerability finding. Bias confidence tiering toward recall, not precision — false negatives are categorically worse than false positives in a security context — but always pair a lowered threshold with explicit tiering to avoid alert fatigue.
