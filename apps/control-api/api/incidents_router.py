import logging

from fastapi import APIRouter, Depends, HTTPException

from ATTENSE_app.events.standard_event import StandardEvent
from ATTENSE_app.reports.report import generate_report
from dependencies.auth import require_events_secret, require_session


logger = logging.getLogger("attense-controller")

router = APIRouter(prefix="/api/incidents")


def _scored_report(incident_id: str, incident) -> dict:
    """Full incident report: the evaluation pipeline (run_bridge) merges the
    durable Wazuh + analyst-action timelines and runs the scoring engine
    (per-rule penalties, TTC decay, difficulty bonus, verdict band) on top of
    the basic ttd/ttc/outcome report.

    Falls back to the plain timestamp report (generate_report) only when the
    pipeline has nothing to score — run_bridge raises ValueError when no durable
    events exist for the incident yet, or its scenario has no rule file. Any
    other error is a real bug and is allowed to surface as a 500.
    """
    from pipeline.bridge import run_bridge

    try:
        report, _events = run_bridge(incident_id)
        return report
    except ValueError as exc:
        logger.warning(
            "Scored report unavailable for %s (%s); returning basic report.",
            incident_id, exc,
        )
        return generate_report(incident)


@router.post("/events", status_code=202)
def ingest_event(
    body: StandardEvent,
    _auth: None = Depends(require_events_secret),
):
    """
    The single validated event-ingestion endpoint (report Phase 2). The body is
    the canonical `StandardEvent` contract -- enum-validated, UTC-aware -- so a
    malformed event is rejected here with 422 instead of being accepted (202)
    and then failing silently inside process_event(). The legacy `timestamp`
    field is still accepted as an alias for `occurred_at`, so the red-team
    engine's existing payload keeps working.

    Service-to-service producers (e.g. the red-team engine emitting
    malicious_action_executed) POST here; the event is adapted down to the
    legacy `Event` and fed to the same controller.process_event() the
    signal-store -> mapped_events.jsonl file-tail path uses -- the red-team
    containers have no access to attense-app's data volume.
    """
    from main import controller

    controller.process_event(body.to_legacy_event_dict())
    return {"status": "accepted", "event_id": body.event_id}


@router.get("/")
def list_incidents(session: dict = Depends(require_session)):
    from main import controller

    return list(controller.incidents.keys())


@router.get("/{incident_id}")
def get_incident(incident_id: str, session: dict = Depends(require_session)):
    from main import controller

    incident = controller.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/report")
def get_incident_report(
    incident_id: str,
    session: dict = Depends(require_session),
):
    from main import controller

    incident = controller.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _scored_report(incident_id, incident)
