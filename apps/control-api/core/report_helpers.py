"""Shared incident-report helper used by both incidents_router.py and
rooms_router.py, so a room's detail view and the standalone incident report
endpoint always agree on the same scored numbers."""

import logging

from attense_core.evaluation.reports import generate_report

logger = logging.getLogger("attense-controller")


def scored_report(incident_id: str, incident) -> tuple[dict, list]:
    """Full incident report: the evaluation pipeline (run_bridge) merges the
    durable Wazuh + analyst-action timelines and runs the scoring engine
    (per-rule penalties, TTC decay, difficulty bonus, verdict band) on top of
    the basic ttd/ttc/outcome report. Returns (report, events) - events is the
    durable timeline run_bridge scored against, needed by some callers (e.g.
    per-member report breakdowns).

    Falls back to the plain timestamp report (generate_report) only when the
    pipeline has nothing to score - run_bridge raises ValueError when no durable
    events exist for the incident yet, or its scenario has no rule file, AND we
    have an in-memory incident to fall back to. If neither has data, re-raises
    so callers can surface a clean 404.
    """
    from pipeline.bridge import run_bridge

    try:
        report, events = run_bridge(incident_id)
        return report, events
    except ValueError as exc:
        if incident is None:
            raise
        logger.warning(
            "Scored report unavailable for %s (%s); returning basic report.",
            incident_id, exc,
        )
        return generate_report(incident), []
