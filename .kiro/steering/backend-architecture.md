---
inclusion: fileMatch
fileMatchPattern: "services/**"
---
# Backend Architecture Rules

These rules apply to any agent working inside `/services/*/` — the Kafka router, consumer, and handler layer.

1. **The Fat Container Pattern:** For local development, all backend workers (Triage, Unpack, Analysis, CVE-Match, Aggregate) run inside a SINGLE Python container. Do not split them into separate microservice containers yet — that only happens via `docker-compose.prod.yml`.

2. **No Celery, anywhere:** Celery is dropped from this system entirely — not as the message transport, and not as a task executor either. The router must be a pure Python process using `confluent-kafka` (Celery's AMQP/UUID-task model is fundamentally incompatible with Kafka's partition-offset model and causes consumer rebalance issues). Sandboxed extraction runs via the `subprocess` module directly from the handler (see rule 6), and the periodic CVE-corpus refresh runs via `APScheduler` — do NOT introduce Celery, a Celery beat, or a separate broker for either.

3. **Kafka Commit Strategy:** Set `enable.auto.commit=False` on every consumer. Every Kafka message must be processed inside a `try/except` block. On exception, push the payload to `firmware.dlq` and MANUALLY commit the offset regardless of success or failure, so one malformed message never stalls the partition.

4. **Handler Boundary Discipline:** Handler functions must NEVER call each other directly in-process (e.g. `handle_unpack(payload)` is forbidden), even though they share memory space in the fat container. All inter-stage communication happens ONLY by producing to the next Kafka topic (e.g. `kafka_producer.send('firmware.triaged', payload)`). This is what allows the switch to fully distributed production containers later with zero code changes.

5. **Topology via Environment Variable:** The router supports a `SERVICES` env var selecting which topics it subscribes to; handler code is identical in every mode. Valid values map 1:1 to handlers:

   | `SERVICES` value | Subscribes to | Handler |
   |---|---|---|
   | `triage` | `firmware.uploaded` | `handle_triage` |
   | `unpack` | `firmware.triaged` | `handle_unpack` |
   | `analysis` | `firmware.extracted` | `handle_analysis` |
   | `match` | `firmware.analyzed` | `handle_cve_match` |
   | `aggregate` | `firmware.matched` | `handle_aggregate` |
   | `all` | all of the above | every handler (local dev) |

   Comma-separated combos are allowed (e.g. `SERVICES=triage,unpack`). The WebSocket **notifier** is a SEPARATE process with its own consumer group that subscribes to `firmware.*` for progress — it is NOT a `SERVICES` value and is never hosted inside the router.

6. **Zombie Process Prevention:** When the Python router executes `binwalk` via the `subprocess` module, implement a graceful `SIGTERM` handler in the parent process to explicitly `.kill()` child processes, preventing zombie memory leaks during hot-reloads.

7. **Testing requirement:** every handler function must have at least one corresponding test that feeds a sample payload from `/sample_payloads/` and asserts the output shape matches the schema steering file exactly. Do not consider a handler "done" without this.
