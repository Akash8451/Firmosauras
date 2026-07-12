"""WebSocket Notification Gateway (Group 3, Task 12).

A SEPARATE process from the router with its OWN Kafka consumer group
(`firmosaurus-notifier`). It subscribes to `firmware.*` for progress and pushes
per-`job_id` updates ("X/N sub-blobs matched") to connected WebSocket clients.

Backpressure is handled per client with a coalescing mailbox: a slow client only
ever sees the LATEST progress snapshot and can never block the Kafka consumer or
the other clients (see `hub.CoalescingMailbox`). It is not a `SERVICES` handler
and is never hosted inside the router (backend-architecture.md rule 5).
"""
