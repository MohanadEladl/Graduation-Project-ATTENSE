import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import user_store
from core.room_manager import (
    ROOMS_DIR,
    create_room,
    join_room_as_red_team,
    list_rooms_for_company,
    spin_down_room,
    spin_up_blueteam,
)
from dependencies.auth import require_session


router = APIRouter(prefix="/api/rooms")


class CreateRoomRequest(BaseModel):
    scenario_id: str


def _require_soc_manager(session: dict) -> None:
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can manage rooms")


def _require_red_team(session: dict) -> None:
    if session["role"] != "red_team":
        raise HTTPException(status_code=403, detail="Only red_team can join rooms")


@router.get("")
def list_rooms(session: dict = Depends(require_session)):
    return list_rooms_for_company(session.get("company_id"))


@router.post("/create")
def create(body: CreateRoomRequest, session: dict = Depends(require_session)):
    _require_soc_manager(session)
    if not session.get("company_id"):
        raise HTTPException(status_code=409, detail="SOC manager is not assigned to a company")
    try:
        return create_room(
            company_id=session["company_id"],
            scenario_id=body.scenario_id,
            created_by=session["username"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{room_id}/start")
def start(room_id: str, session: dict = Depends(require_session)):
    _require_soc_manager(session)
    try:
        return spin_up_blueteam(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/{room_id}/join")
def join(room_id: str, session: dict = Depends(require_session)):
    _require_red_team(session)
    room_path = ROOMS_DIR / f"{room_id}.json"
    if not room_path.exists():
        raise HTTPException(status_code=404, detail="Room not found")
    with room_path.open("r", encoding="utf-8") as room_file:
        room = json.load(room_file)
    if room.get("company_id") != session.get("company_id"):
        raise HTTPException(status_code=403, detail="Room belongs to a different company")
    try:
        room = join_room_as_red_team(room_id, session["username"])
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    user = user_store.get_user_by_username(session["username"])
    if user is not None:
        user_store.set_active_room(user["id"], room_id)
    return room


@router.delete("/{room_id}")
def delete(room_id: str, session: dict = Depends(require_session)):
    _require_soc_manager(session)
    try:
        spin_down_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"message": "Room closed successfully"}


@router.get("/{room_id}")
def get(room_id: str, session: dict = Depends(require_session)):
    room_path = ROOMS_DIR / f"{room_id}.json"
    if not room_path.exists():
        raise HTTPException(status_code=404, detail="Room not found")
    with room_path.open("r", encoding="utf-8") as room_file:
        room = json.load(room_file)

    # ciso has company_id=None, meaning cross-company oversight (same
    # convention as list_pending/confirm) — everyone else must match.
    if session["role"] != "ciso" and session.get("company_id") != room.get("company_id"):
        raise HTTPException(status_code=403, detail="Room belongs to a different company")

    from main import controller
    from ATTENSE_app.reports.report import generate_report

    incident_ids = room.get("incidents") or (
        [room["incident_id"]] if room.get("incident_id") else []
    )
    detail = []
    for incident_id in incident_ids:
        incident = controller.incidents.get(incident_id)
        if incident is None:
            detail.append({"incident_id": incident_id, "status": "no_events"})
        else:
            detail.append({
                "incident_id": incident_id,
                "status": incident.status,
                "report": generate_report(incident),
            })
    room["incidents_detail"] = detail
    return room
