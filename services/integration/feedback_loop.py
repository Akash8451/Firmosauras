"""Task 14 — per-component-family confidence-threshold recalibration.

The analyst feedback loop closes here: analysts submit ``confirmed`` /
``false_positive`` verdicts on CVE matches (persisted to ``analyst_feedback``,
SCHEMA.md §6); this module reads those rows, aggregates them per component family,
and adjusts that family's confidence-tier thresholds — then installs the result
into ``services.cve_matching.config`` via ``set_family_thresholds``, which is the
exact store Task 10's matcher/tiering reads from. No thresholds are hardcoded here;
we always recompute from a base ``ThresholdConfig`` so repeated runs are idempotent.

Adjustment policy (analysis-modules-rbac.md AI principle — recall-biased, but pair
a lowered threshold with tiering to avoid alert fatigue):
  * A family whose analysts keep marking matches ``false_positive`` is too loose,
    so we RAISE its thresholds (demand higher similarity) to cut the noise.
  * A family that is almost always ``confirmed`` can afford more recall, so we
    LOWER its thresholds slightly to surface more candidates.
  * In between, leave the family on the locked defaults.

Everything here is pure given its inputs; the pg-backed feedback reader and
cve_id->family resolver are injectable so the logic is unit-testable offline.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from services.cve_matching import config
from services.cve_matching.config import DEFAULT_THRESHOLDS, ThresholdConfig
from services.cve_matching.feedback import Feedback

log = logging.getLogger("integration.feedback_loop")

# Only decided verdicts drive recalibration (needs_review is deliberately ignored).
_DECIDED = ("confirmed", "false_positive")

# Recalibration knobs. A family is "too loose" above the stricten rate and
# "safe to loosen" below the loosen rate; deltas are small so a single sprint of
# feedback nudges rather than lurches the thresholds.
FP_RATE_STRICTEN = 0.5   # >= half of decided verdicts are false positives -> stricter
FP_RATE_LOOSEN = 0.1     # <= 10% false positives -> a touch more recall
STRICTEN_DELTA = 0.05
LOOSEN_DELTA = 0.03
MIN_SAMPLES = 1          # need at least this many decided verdicts to act

# cve_id -> family name (or None if unknown / out of scope).
FamilyResolver = Callable[[str], Optional[str]]
FeedbackReader = Callable[[], List[Feedback]]


@dataclass
class FamilyStats:
    family: str
    confirmed: int = 0
    false_positive: int = 0

    @property
    def decided(self) -> int:
        return self.confirmed + self.false_positive

    @property
    def fp_rate(self) -> float:
        return self.false_positive / self.decided if self.decided else 0.0


def _valid_thresholds(high: float, possible: float, low: float) -> ThresholdConfig:
    """Clamp to [0,1] and enforce low <= possible <= high (SCHEMA.md invariant)."""
    high = min(max(high, 0.0), 1.0)
    possible = min(max(possible, 0.0), 1.0)
    low = min(max(low, 0.0), 1.0)
    # Enforce ordering by squeezing the lower bounds under the upper ones.
    possible = min(possible, high)
    low = min(low, possible)
    return ThresholdConfig(high_confidence=high, possible=possible, low_confidence=low)


def adjust_for_fp_rate(base: ThresholdConfig, fp_rate: float) -> ThresholdConfig:
    """Return the recalibrated thresholds for a family given its false-positive rate."""
    if fp_rate >= FP_RATE_STRICTEN:
        d = STRICTEN_DELTA
        return _valid_thresholds(
            base.high_confidence + d, base.possible + d, base.low_confidence + d
        )
    if fp_rate <= FP_RATE_LOOSEN:
        d = LOOSEN_DELTA
        return _valid_thresholds(
            base.high_confidence - d, base.possible - d, base.low_confidence - d
        )
    return base


def aggregate(
    rows: Iterable[Feedback], family_resolver: FamilyResolver
) -> Dict[str, FamilyStats]:
    """Tally confirmed/false-positive verdicts per resolved component family."""
    stats: Dict[str, FamilyStats] = {}
    for row in rows:
        if row.verdict not in _DECIDED:
            continue
        family = family_resolver(row.cve_id)
        if not family:
            continue  # unknown / out-of-scope CVE — can't attribute to a family
        s = stats.setdefault(family, FamilyStats(family))
        if row.verdict == "confirmed":
            s.confirmed += 1
        else:
            s.false_positive += 1
    return stats


def recalibrate(
    rows: Iterable[Feedback],
    family_resolver: FamilyResolver,
    *,
    base: ThresholdConfig = DEFAULT_THRESHOLDS,
    min_samples: int = MIN_SAMPLES,
    install: bool = True,
) -> Dict[str, ThresholdConfig]:
    """Recalibrate per-family thresholds from feedback and (optionally) install them.

    Returns the map of families whose thresholds CHANGED from ``base``. Computing
    from ``base`` every time keeps this idempotent — the same feedback always
    yields the same thresholds regardless of how many times it runs.
    """
    stats = aggregate(rows, family_resolver)
    updated: Dict[str, ThresholdConfig] = {}
    for family, s in stats.items():
        if s.decided < min_samples:
            continue
        new_cfg = adjust_for_fp_rate(base, s.fp_rate)
        if new_cfg == base:
            continue  # no change warranted
        if install:
            config.set_family_thresholds(family, new_cfg)
            log.info(
                "recalibrated %s: fp_rate=%.2f -> high=%.2f possible=%.2f low=%.2f",
                family, s.fp_rate, new_cfg.high_confidence, new_cfg.possible, new_cfg.low_confidence,
            )
        updated[family] = new_cfg
    return updated


def current_thresholds() -> List[dict]:
    """Snapshot every scoped family's active thresholds + whether it's recalibrated.

    Drives the admin ``GET /config/thresholds`` view. A family with an installed
    override reads ``recalibrated``; otherwise it reflects the locked default.
    """
    rows: List[dict] = []
    for fam in config.COMPONENT_FAMILIES:
        override = config.FAMILY_THRESHOLDS.get(fam.name)
        cfg = override or config.DEFAULT_THRESHOLDS
        rows.append(
            {
                "family": fam.name,
                "high_confidence": cfg.high_confidence,
                "possible": cfg.possible,
                "low_confidence": cfg.low_confidence,
                "source": "recalibrated" if override is not None else "default",
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# pg-backed sources (best-effort, lazy — mirror feedback.py / jobs_status.py). #
# Injectable so the HTTP layer and tests can supply fakes without a database.  #
# --------------------------------------------------------------------------- #
_reader: Optional[FeedbackReader] = None
_resolver: Optional[FamilyResolver] = None


def set_sources(reader: Optional[FeedbackReader], resolver: Optional[FamilyResolver]) -> None:
    """Override the feedback reader + family resolver (tests / custom wiring)."""
    global _reader, _resolver
    _reader = reader
    _resolver = resolver


def get_reader() -> FeedbackReader:
    return _reader or _pg_feedback_reader


def get_resolver() -> FamilyResolver:
    return _resolver or _pg_family_resolver


def _pg_feedback_reader() -> List[Feedback]:
    """Read ALL analyst_feedback rows (across jobs). Best-effort; [] on any error."""
    try:
        import psycopg  # lazy
    except Exception:
        log.warning("psycopg unavailable; recalibration has no feedback to read")
        return []
    try:
        with psycopg.connect(config.postgres_dsn(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT feedback_id, job_id, cve_id, verdict, submitted_by, submitted_at "
                    "FROM analyst_feedback;"
                )
                return [
                    Feedback(
                        feedback_id=r[0], job_id=r[1], cve_id=r[2],
                        verdict=r[3], submitted_by=r[4], submitted_at=str(r[5]),
                    )
                    for r in cur.fetchall()
                ]
    except Exception:
        log.warning("could not read analyst_feedback for recalibration", exc_info=True)
        return []


def _pg_family_resolver(cve_id: str) -> Optional[str]:
    """Resolve a cve_id to a component family via the local corpus (air-gapped)."""
    try:
        import psycopg  # lazy
    except Exception:
        return None
    try:
        with psycopg.connect(config.postgres_dsn(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT family FROM cve_corpus WHERE cve_id = %s AND family IS NOT NULL "
                    "LIMIT 1;",
                    (cve_id,),
                )
                row = cur.fetchone()
                return row[0] if row else None
    except Exception:
        return None


def recalibrate_now(*, install: bool = True) -> Dict[str, ThresholdConfig]:
    """On-demand recalibration using the configured (pg-backed) sources."""
    return recalibrate(get_reader()(), get_resolver(), install=install)
