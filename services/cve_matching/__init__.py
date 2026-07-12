"""Group 3 — CVE intelligence package.

Home for the local, air-gapped CVE-matching core (SCHEMA.md §8):

  * `config`     — component families, per-family confidence thresholds, env config.
  * `cpe`        — CPE 2.3 parse/build + family resolution.
  * `embeddings` — MiniLM (all-MiniLM-L6-v2 -> 384-dim) wrapper, lazy + injectable.
  * `corpus`     — pgvector repository (exact CPE lookup + similarity search) and an
                   in-memory fake used by tests.
  * `nvd_etl`    — offline NVD bulk/incremental ingest + APScheduler refresh. This is
                   the ONLY module that ever touches the network, and it is never on the
                   runtime query path.
  * `tiering`    — similarity-score -> confidence tier using per-family config.
  * `normalize`  — regex normalization of messy version strings -> (vendor, product, version).
  * `llm`        — optional OpenAI-compatible narration (POSSIBLE/LOW only, graceful).
  * `matcher`    — orchestrates the deterministic match pipeline used by the handler.

The runtime query path (exact CPE lookup + pgvector similarity search) NEVER makes an
external network call — see `.kiro/steering/hard-constraints.md` (Data Source Rules) and
SCHEMA.md §8 (air-gapped core vs optional LLM layer).
"""
