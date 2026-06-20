from fastapi import APIRouter, Depends, HTTPException

from ATTENSE_app.reports.report import generate_report
from dependencies.auth import require_session


router = APIRouter(prefix="/api/incidents")


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
