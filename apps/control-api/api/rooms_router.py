from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import user_store
from core.room_manager import (
    accept_invite,
    enter_room,
    get_room,
    create_room,
    hive_credentials,
    join_room_as_red_team,
    list_invites_for_email,
    list_rooms_for_company,
    prefire_room,
    room_lobby,
    spin_down_room,
    spin_up_blueteam,
    start_blue_team,
)
from dependencies.auth import require_session


router = APIRouter(prefix="/api/rooms")

BLUE_ROLES = {"soc_manager", "soc_l1", "soc_l2"}


class CreateRoomRequest(BaseModel):
    scenario_id: str


class EnterRoomRequest(BaseModel):
    mode: str = "solo"
    teammates: list[str] = []


def _require_blue(session: dict) -> None:
    if session["role"] not in BLUE_ROLES:
        raise HTTPException(status_code=403, detail="Only Blue Team users can enter rooms")


def _session_email(session: dict) -> str:
    # Self-registered users store their email as their username, but resolve the
    # authoritative email from the user record when available.
    user = user_store.get_user_by_username(session["username"])
    return (user or {}).get("email") or session["username"]


def _thehive_envelope(room: dict, room_id: str, session: dict | None = None) -> dict:
    thehive = {
        "launch_url": room.get("hive_launch_url"),
        "incident_id": room.get("incident_id"),
        "room_id": room_id,
    }
    if session is not None:
        # The requesting analyst's own TheHive web-login credentials, so the UI
        # can show how to sign in to the incident inside the iframe.
        creds = hive_credentials(session["username"])
        thehive["login"] = creds["login"]
        thehive["password"] = creds["password"]
    return {**room, "thehive": thehive}


def _require_soc_manager(session: dict) -> None:
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can manage rooms")


def _require_red_team(session: dict) -> None:
    if session["role"] != "red_team":
        raise HTTPException(status_code=403, detail="Only red_team can join rooms")


@router.get("")
def list_rooms(session: dict = Depends(require_session)):
    # Blue Team has global visibility: any SOC/CISO user sees every room across
    # the range, not just their own company's. Red Team stays scoped to the
    # rooms it has joined (its own company). Passing None returns all rooms.
    if session["role"] != "red_team":
        return list_rooms_for_company(None)
    return list_rooms_for_company(session.get("company_id"))


@router.get("/invites")
def invites(session: dict = Depends(require_session)):
    """Rooms the current Blue Team user has been invited to but not yet joined.

    Declared before GET /{room_id} so the fixed 'invites' path is not captured
    as a room id. Polled by the Blue Team UI to surface in-app invitations.
    """
    _require_blue(session)
    return list_invites_for_email(_session_email(session))


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
    try:
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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


@router.post("/{room_id}/prefire")
def prefire(room_id: str, session: dict = Depends(require_session)):
    _require_red_team(session)
    try:
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if room.get("company_id") != session.get("company_id"):
        raise HTTPException(status_code=403, detail="Room belongs to a different company")
    if session["username"] not in room.get("red_team_members", []):
        raise HTTPException(status_code=403, detail="Red team user has not joined this room")
    try:
        return prefire_room(room_id, session["username"])
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{room_id}/blue-start")
def blue_start(room_id: str, session: dict = Depends(require_session)):
    if session["role"] not in {"soc_manager", "soc_l1", "soc_l2"}:
        raise HTTPException(status_code=403, detail="Only Blue Team users can start the exercise")
    try:
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # Global Blue Team visibility: any Blue Team user may start any room,
    # regardless of which company created it.
    try:
        room = start_blue_team(room_id, session["username"])
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _thehive_envelope(room, room_id, session)


@router.post("/{room_id}/enter")
def enter(room_id: str, body: EnterRoomRequest, session: dict = Depends(require_session)):
    """Enter a room solo or with a team. The entering user becomes the room's
    SOC manager (minting the shared Hive key) and any teammate emails are stored
    as pending invites."""
    _require_blue(session)
    try:
        room = enter_room(
            room_id,
            session["username"],
            mode=body.mode,
            teammates=body.teammates,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _thehive_envelope(room, room_id, session)


@router.post("/{room_id}/accept")
def accept(room_id: str, session: dict = Depends(require_session)):
    """An invited Blue Team user joins the room, landing in its shared Hive org."""
    _require_blue(session)
    try:
        room = accept_invite(room_id, session["username"], email=_session_email(session))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _thehive_envelope(room, room_id, session)


@router.get("/{room_id}/lobby")
def lobby(room_id: str, session: dict = Depends(require_session)):
    """Lightweight join-status view of a room for the lobby poll loop."""
    _require_blue(session)
    try:
        result = room_lobby(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    creds = hive_credentials(session["username"])
    result["thehive_login"] = creds["login"]
    result["thehive_password"] = creds["password"]
    return result


@router.post("/{room_id}/end")
def end_incident(room_id: str, session: dict = Depends(require_session)):
    if session["role"] not in {"soc_manager", "soc_l1", "soc_l2"}:
        raise HTTPException(status_code=403, detail="Only Blue Team users can end the incident")
    try:
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # Global Blue Team visibility: any Blue Team user may end any room.
    try:
        room = spin_down_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        **room,
        "message": "Incident ended. Report is ready when event data is available.",
    }


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
    try:
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Blue Team (any SOC/CISO role) has global room visibility, consistent with
    # list_rooms; only red_team stays scoped to its own company's rooms.
    if session["role"] == "red_team" and session.get("company_id") != room.get("company_id"):
        raise HTTPException(status_code=403, detail="Room belongs to a different company")

    from main import controller
    from attense_core.evaluation.reports import generate_report
    from api.incidents_router import _serialize_report

    incident_ids = room.get("incidents") or (
        [room["incident_id"]] if room.get("incident_id") else []
    )
    room_timing = {
        "exercise_mode": room.get("exercise_mode", "live"),
        "attack_started_at": room.get("attack_started_at"),
        "attack_completed_at": room.get("attack_completed_at"),
        "packaged_at": room.get("packaged_at"),
        "blue_started_at": room.get("blue_started_at"),
        "blue_started_by": room.get("blue_started_by"),
    }
    detail = []
    for incident_id in incident_ids:
        incident = controller.incidents.get(incident_id)
        if incident is None:
            detail.append({"incident_id": incident_id, "status": "no_events"})
        else:
            report = generate_report(incident)
            report["room_timing"] = room_timing
            detail.append({
                "incident_id": incident_id,
                "status": incident.status,
                "report": _serialize_report(report),
            })
    room["incidents_detail"] = detail
    return room

