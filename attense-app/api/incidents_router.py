from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ATTENSE_app.reports.report import generate_report
from dependencies.auth import require_events_secret, require_session


router = APIRouter(prefix="/api/incidents")


class IncidentEventRequest(BaseModel):
    event_id: str
    incident_id: str
    scenario_id: str
    actor_id: str
    target_id: str
    event_type: str
    actor_type: str
    target_type: str
    timestamp: str | None = None
    outcome: str | None = None
    metadata: dict[str, Any] | None = None


@router.post("/events", status_code=202)
def ingest_event(
    body: IncidentEventRequest,
    _auth: None = Depends(require_events_secret),
):
    """
    Service-to-service event ingestion (e.g. the red-team engine emitting
    malicious_action_executed). Feeds the same controller.process_event()
    that the signal-store -> mapped_events.jsonl file-tail path uses, just
    triggered by an HTTP POST instead of a new line in that file -- the
    red-team containers have no access to attense-app's data volume.
    """
    from main import controller

    controller.process_event(body.model_dump())
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
    return generate_report(incident)
