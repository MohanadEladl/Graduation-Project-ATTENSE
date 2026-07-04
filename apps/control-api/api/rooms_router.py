from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import user_store
from core.room_manager import (
    accept_invite,
    enter_room,
    ensure_member_hive_login,
    get_room,
    hive_credentials,
    list_invites_for_email,
    list_rooms_for_company,
    resync_room_alerts,
    room_lobby,
    spin_down_room,
    start_blue_team,
)
from dependencies.auth import require_session


router = APIRouter(prefix="/api/rooms")

BLUE_ROLES = {"soc_manager", "soc_l1", "soc_l2"}


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
    # The requesting analyst's own (dynamic, per-user) TheHive web-login
    # credentials, scoped to THIS room's own org. Provision on demand: the
    # caller may be viewing this room via Blue Team's global visibility
    # without ever having entered it. Only surfaced once the room actually
    # has its own org (someone has entered/accepted at least once) - a room
    # nobody has opened yet has no org to log into, and no shared/global org
    # is used as a fallback (that fallback was the isolation leak).
    if session is not None and room.get("hive_org"):
        ensure_member_hive_login(room_id, session["username"])
        creds = hive_credentials(session["username"])
        thehive["login"] = creds["login"]
        thehive["password"] = creds["password"]
    return {**room, "thehive": thehive}


def _require_soc_manager(session: dict) -> None:
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can manage rooms")


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


@router.post("/{room_id}/replay-alerts")
def replay_alerts(room_id: str, session: dict = Depends(require_session)):
    """Re-push a room's stored detections into TheHive so its alerts appear.

    Called by the Blue Team UI whenever a room is opened - including a closed /
    past room - so the analyst sees the room's alerts in TheHive even if the
    original delivery never happened. Idempotent: TheHive dedups by sourceRef.
    """
    _require_blue(session)
    try:
        result = resync_room_alerts(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"room_id": room_id, **(result or {})}


@router.get("/{room_id}/lobby")
def lobby(room_id: str, session: dict = Depends(require_session)):
    """Lightweight join-status view of a room for the lobby poll loop."""
    _require_blue(session)
    try:
        result = room_lobby(room_id)
        room = get_room(room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # See _thehive_envelope: only surface credentials once the room has its
    # own org - no shared/global org fallback.
    if room.get("hive_org"):
        ensure_member_hive_login(room_id, session["username"])
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
    from core.report_helpers import scored_report
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
            report, _events = scored_report(incident_id, incident)
            report["room_timing"] = room_timing
            detail.append({
                "incident_id": incident_id,
                "status": incident.status,
                "report": _serialize_report(report),
            })
    room["incidents_detail"] = detail
    # Blue Team users get the shared TheHive login creds + launch url on every
    # GET, so the UI can open TheHive for ANY room it shows - including a closed /
    # past room that was never entered this session (needed to re-view its alerts).
    if session["role"] in BLUE_ROLES:
        return _thehive_envelope(room, room_id, session)
    return room

