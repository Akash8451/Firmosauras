"""CLI entrypoint for the CVE corpus ETL + periodic refresh (Task 9).

Wires the REAL pgvector store + MiniLM embedder and either:
  * runs a one-shot full ingest (`--full`), or
  * runs an incremental refresh once (`--incremental`), or
  * starts the APScheduler daemon that refreshes on an interval (default).

The runtime query path never imports this module; it is an operational tool.

    # one-shot full bulk ingest (scoped to our families)
    python -m services.cve_matching.refresh_daemon --full

    # start the periodic refresh daemon (every 24h)
    python -m services.cve_matching.refresh_daemon --interval-hours 24
"""
from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timedelta, timezone

from . import nvd_etl
from .corpus import PgVectorCorpus
from .embeddings import MiniLmEmbedder

log = logging.getLogger("cve_matching.refresh_daemon")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CVE corpus ETL + refresh")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="one-shot full bulk ingest")
    mode.add_argument("--incremental", action="store_true", help="one-shot incremental refresh")
    parser.add_argument("--interval-hours", type=float, default=24.0)
    parser.add_argument("--lookback-hours", type=float, default=26.0)
    parser.add_argument("--max-records", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    repo = PgVectorCorpus()
    embedder = MiniLmEmbedder()

    if args.full:
        result = nvd_etl.run_full_etl(repo, embedder=embedder, max_records=args.max_records)
        log.info("full ETL complete: %s", result)
        return 0

    if args.incremental:
        since = datetime.now(timezone.utc) - timedelta(hours=args.lookback_hours)
        result = nvd_etl.run_incremental_refresh(repo, since=since, embedder=embedder)
        log.info("incremental refresh complete: %s", result)
        return 0

    # Daemon mode: schedule periodic incremental refreshes and block.
    scheduler = nvd_etl.start_refresh_scheduler(
        repo,
        interval_hours=args.interval_hours,
        lookback_hours=args.lookback_hours,
        embedder=embedder,
    )
    try:
        while True:
            time.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        log.info("shutting down refresh scheduler")
        scheduler.shutdown(wait=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
