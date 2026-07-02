from fastapi import APIRouter, Depends

from core import mission_store
from dependencies.auth import require_events_secret, require_session

router = APIRouter(prefix="/api/missions")


@router.post("/snapshot", status_code=202)
def record_snapshot(body: dict, _auth: None = Depends(require_events_secret)):
    """Internal dual-write endpoint used by red-team-backend.

    The red service keeps its legacy session JSON, and posts full snapshots here
    so Postgres can become the reporting/history source without a hard cutover.
    """
    mission_store.record_mission_snapshot(body)
    return {"status": "accepted", "session_id": body.get("session_id")}


@router.post("/blue-action", status_code=202)
def record_blue_action(body: dict, _auth: None = Depends(require_events_secret)):
    """Internal dual-write endpoint used by blue-team-api.

    Blue Team analyst actions and emitted events are forwarded here so Postgres
    can track blue-side activity alongside the red-team mission records.
    """
    mission_store.record_blue_action(
    body,
    incident_id=body.get("incident_id"),
    room_key=body.get("room_id"),
    )
    return {"status": "accepted"}


@router.get("")
def list_missions(completed: bool | None = None, session: dict = Depends(require_session)):
    return mission_store.list_missions_for_user(session["username"], completed=completed)


@router.get("/completed")
def list_completed_missions(session: dict = Depends(require_session)):
    return mission_store.list_missions_for_user(session["username"], completed=True)