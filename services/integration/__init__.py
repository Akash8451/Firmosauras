"""Group 4 (Surface & Integration) backend surface.

New, Group-4-owned modules only — this package NEVER edits files owned by other
groups. It composes the existing gateway/notifier/cve-matching building blocks:

  * ``feedback_loop`` — the Task 14 feedback loop: read ``analyst_feedback`` rows,
    recalibrate per-component-family confidence thresholds, and install them into
    the ``services.cve_matching.config`` store the matcher already reads from.
  * ``job_index``     — the Task 14 per-job RAG vector index lifecycle
    (build on completion, query strictly job-scoped, TTL teardown, cross-job
    isolation).
  * ``http``          — the Group-4 HTTP surface (feedback + config endpoints)
    mounted on top of the gateway app via ``include_router`` (no gateway edits).
  * ``app``           — the composed integration entrypoint used for the Task 15
    no-mock end-to-end run.
"""
