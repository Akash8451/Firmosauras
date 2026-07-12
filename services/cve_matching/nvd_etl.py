"""NVD CVE corpus ETL + incremental refresh (Task 9).

This is the ONLY module in the CVE core that touches the network, and it is
NEVER imported by the runtime query path (the matcher imports `corpus` /
`embeddings` / `cpe`, not this). Per hard-constraints.md (Data Source Rules) the
NVD feed is pulled OFFLINE / on a schedule, embedded into local pgvector, and the
runtime lookup then hits only the local index.

Pipeline:
  1. Fetch NVD 2.0 vulnerability JSON (full bulk, or incremental via
     `lastModStartDate`). Network access is injected (`fetch`) so tests never
     hit the wire.
  2. Scope to the component families we normalize (config.COMPONENT_FAMILIES) —
     we do NOT embed all 250k+ CVEs, only in-scope CPEs, keeping the index small.
  3. Embed each in-scope (cve, cpe) with all-MiniLM-L6-v2 (384-dim).
  4. Upsert into the corpus (idempotent on (cve_id, cpe_string)).

Incremental refresh runs via APScheduler (NOT Celery / NOT a Celery beat), per
backend-architecture.md rule 2.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, List, Optional, Sequence

from . import config, cpe as cpe_mod
from .corpus import CorpusRepository, CveRecord, corpus_text
from .embeddings import Embedder, get_embedder

log = logging.getLogger("cve_matching.etl")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Type of the injectable network fetcher: (params) -> parsed NVD JSON dict.
FetchFn = Callable[[dict], dict]


# --------------------------------------------------------------------------- #
# NVD JSON parsing (works on the 2.0 API shape and the bulk feed).            #
# --------------------------------------------------------------------------- #
def iter_cve_objects(nvd_json: dict) -> Iterator[dict]:
    """Yield each `cve` object from an NVD 2.0 response.

    2.0 shape: {"vulnerabilities": [{"cve": {...}}, ...]}. Tolerates a bare list
    of cve objects too (useful for hand-written test fixtures).
    """
    if isinstance(nvd_json, list):
        for item in nvd_json:
            if isinstance(item, dict):
                yield item.get("cve", item)
        return
    for item in nvd_json.get("vulnerabilities", []):
        if isinstance(item, dict) and "cve" in item:
            yield item["cve"]


def description_of(cve: dict) -> str:
    """English description text of a CVE object."""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    descs = cve.get("descriptions", [])
    return descs[0].get("value", "") if descs else ""


def cpes_of(cve: dict) -> List[str]:
    """All CPE criteria strings referenced by a CVE's configurations."""
    out: List[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                crit = cm.get("criteria")
                if crit:
                    out.append(crit)
    return out


def records_from_cve(cve: dict, *, embed: bool = True, embedder: Optional[Embedder] = None) -> List[CveRecord]:
    """Build the in-scope corpus records for a single CVE (one per scoped CPE).

    Out-of-scope CPEs are dropped here — this is the scoping step that keeps the
    corpus small. When `embed` is True each record's embedding is populated.
    """
    cve_id = cve.get("id") or cve.get("cve_id")
    if not cve_id:
        return []
    description = description_of(cve)

    scoped = cpe_mod.in_scope_cpes(cpes_of(cve))
    records: List[CveRecord] = []
    for cpe_string in scoped:
        family = cpe_mod.family_for_cpe(cpe_string)
        records.append(
            CveRecord(
                cve_id=cve_id,
                cpe_string=cpe_string,
                description=description,
                family=family,
            )
        )

    if embed and records:
        emb = embedder or get_embedder()
        vectors = emb.encode_batch([corpus_text(r) for r in records])
        for rec, vec in zip(records, vectors):
            rec.embedding = vec
    return records


# --------------------------------------------------------------------------- #
# ETL drivers.                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class EtlResult:
    cves_seen: int
    records_upserted: int
    families: dict  # family -> count


def ingest_cves(
    repo: CorpusRepository,
    cves: Iterable[dict],
    *,
    embedder: Optional[Embedder] = None,
    batch_size: int = 200,
) -> EtlResult:
    """Scope, embed, and upsert an iterable of NVD `cve` objects into the corpus."""
    emb = embedder or get_embedder()
    seen = 0
    upserted = 0
    families: dict = {}
    batch: List[CveRecord] = []

    def flush() -> None:
        nonlocal upserted
        if batch:
            upserted += repo.upsert(batch)
            batch.clear()

    for cve in cves:
        seen += 1
        recs = records_from_cve(cve, embed=True, embedder=emb)
        for r in recs:
            families[r.family] = families.get(r.family, 0) + 1
        batch.extend(recs)
        if len(batch) >= batch_size:
            flush()
    flush()

    log.info("ETL ingest: cves_seen=%d records_upserted=%d families=%s", seen, upserted, families)
    return EtlResult(cves_seen=seen, records_upserted=upserted, families=families)


# --------------------------------------------------------------------------- #
# Network fetch (injectable; the ONLY code here that hits the wire).           #
# --------------------------------------------------------------------------- #
def _http_get_json(url: str, params: dict, *, timeout: float = 30.0) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    full = f"{url}?{query}" if query else url
    req = urllib.request.Request(full, headers={"User-Agent": "firmosaurus-cve-etl/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted host)
        return json.loads(resp.read().decode("utf-8"))


def fetch_nvd_page(params: dict) -> dict:
    """Default network fetcher for a single NVD 2.0 page."""
    return _http_get_json(NVD_API_URL, params)


def fetch_nvd(
    *,
    results_per_page: int = 2000,
    last_mod_start: Optional[datetime] = None,
    last_mod_end: Optional[datetime] = None,
    max_records: Optional[int] = None,
    fetch: FetchFn = fetch_nvd_page,
) -> Iterator[dict]:
    """Yield NVD `cve` objects, paginating the 2.0 API.

    `fetch` is injectable so tests supply canned pages and NO network call is made.
    `last_mod_start`/`last_mod_end` drive the incremental refresh window.
    """
    start_index = 0
    total = None
    while True:
        params: dict = {"resultsPerPage": results_per_page, "startIndex": start_index}
        if last_mod_start is not None:
            params["lastModStartDate"] = last_mod_start.astimezone(timezone.utc).isoformat()
        if last_mod_end is not None:
            params["lastModEndDate"] = last_mod_end.astimezone(timezone.utc).isoformat()

        page = fetch(params)
        if total is None:
            total = page.get("totalResults")

        count = 0
        for cve in iter_cve_objects(page):
            yield cve
            count += 1
            start_index += 1
            if max_records is not None and start_index >= max_records:
                return

        # Stop when a page returns nothing or we've paged past the total.
        if count == 0:
            return
        if total is not None and start_index >= total:
            return


def run_full_etl(
    repo: CorpusRepository,
    *,
    embedder: Optional[Embedder] = None,
    fetch: FetchFn = fetch_nvd_page,
    max_records: Optional[int] = None,
) -> EtlResult:
    """One-shot full ingest: ensure schema, then pull + scope + embed + upsert."""
    repo.ensure_schema()
    cves = fetch_nvd(fetch=fetch, max_records=max_records)
    return ingest_cves(repo, cves, embedder=embedder)


def run_incremental_refresh(
    repo: CorpusRepository,
    *,
    since: datetime,
    until: Optional[datetime] = None,
    embedder: Optional[Embedder] = None,
    fetch: FetchFn = fetch_nvd_page,
) -> EtlResult:
    """Incremental refresh: ingest only CVEs modified since `since` and upsert.

    Idempotent (upsert on (cve_id, cpe_string)), so a re-run over an overlapping
    window never duplicates rows — it just re-writes them.
    """
    repo.ensure_schema()
    cves = fetch_nvd(last_mod_start=since, last_mod_end=until, fetch=fetch)
    return ingest_cves(repo, cves, embedder=embedder)


# --------------------------------------------------------------------------- #
# APScheduler periodic refresh (NOT Celery — backend-architecture.md rule 2).  #
# --------------------------------------------------------------------------- #
def start_refresh_scheduler(
    repo: CorpusRepository,
    *,
    interval_hours: float = 24.0,
    lookback_hours: float = 26.0,
    embedder: Optional[Embedder] = None,
    fetch: FetchFn = fetch_nvd_page,
):
    """Start a background APScheduler job that periodically refreshes the corpus.

    Each run pulls the NVD incremental window (last `lookback_hours`, slightly
    wider than the interval so nothing is missed at the boundary) and upserts.
    Returns the started scheduler so the caller can shut it down.
    """
    from apscheduler.schedulers.background import BackgroundScheduler  # lazy

    def _job() -> None:
        since = datetime.now(timezone.utc) - _timedelta_hours(lookback_hours)
        try:
            result = run_incremental_refresh(repo, since=since, embedder=embedder, fetch=fetch)
            log.info("scheduled refresh done: %s", result)
        except Exception:  # never let a failed refresh kill the scheduler thread
            log.exception("scheduled CVE refresh failed")

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(_job, "interval", hours=interval_hours, id="cve_corpus_refresh")
    scheduler.start()
    log.info("CVE corpus refresh scheduler started: every %sh", interval_hours)
    return scheduler


def _timedelta_hours(hours: float):
    from datetime import timedelta

    return timedelta(hours=hours)
