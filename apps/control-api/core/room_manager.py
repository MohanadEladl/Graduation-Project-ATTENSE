import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import docker
import httpx

from core import company_store, port_pool, user_store

logger = logging.getLogger(__name__)


TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
ROOMS_DIR = Path(TEMP_PATH) / "rooms"
BLUETEAM_IMAGE = "attense-app-blueteam"
DOCKER_NETWORK = "attense_net"
SIGNAL_STORE_URL = os.getenv("SIGNAL_STORE_URL", "http://signal-store:8000")
SIGNAL_STORE_CONFIG_SECRET = os.getenv("SIGNAL_STORE_CONFIG_SECRET", "")


def _configure_signal_store_incident(incident_id: Optional[str]) -> None:
    """Tell the long-lived signal-store which active room owns new alerts.

    Wazuh alerts do not contain ATTENSE room IDs.  Without this handoff they
    keep using the static container INCIDENT_ID and cannot join the red-team
    event stream for a room created after compose startup.
    """
    if not SIGNAL_STORE_CONFIG_SECRET:
        raise RuntimeError("SIGNAL_STORE_CONFIG_SECRET is not configured")
    try:
        response = httpx.put(
            f"{SIGNAL_STORE_URL.rstrip('/')}/configuration/active-incident",
            json={"incident_id": incident_id},
            headers={"X-Signal-Store-Secret": SIGNAL_STORE_CONFIG_SECRET},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to configure signal-store incident: {exc}") from exc


def _room_path(room_id: str) -> Path:
    return ROOMS_DIR / f"{room_id}.json"


def _load_room(room_id: str) -> dict:
    path = _room_path(room_id)
    if not path.exists():
        raise ValueError(f"Room not found: {room_id}")

    with path.open("r", encoding="utf-8") as room_file:
        return json.load(room_file)


def _save_room(room: dict) -> None:
    ROOMS_DIR.mkdir(parents=True, exist_ok=True)
    with _room_path(room["room_id"]).open("w", encoding="utf-8") as room_file:
        json.dump(room, room_file, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_room(company_id: str, scenario_id: str, created_by: str) -> dict:
    company = company_store.get_company(company_id)
    if company is None:
        raise ValueError(f"Company not found: {company_id}")
    if company["status"] != "active":
        raise RuntimeError("Company must be confirmed before creating rooms")
    room_id = str(uuid.uuid4())
    incident_id = str(uuid.uuid4())

    room = {
        "room_id": room_id,
        "company_id": company_id,
        "incident_id": incident_id,
        "incidents": [incident_id],
        "scenario_id": scenario_id,
        "exercise_mode": "deferred",
        "internal_url": f"http://blueteam_{room_id}:8010",
        "status": "created",
        "blue_team_members": [],
        "red_team_members": [],
        "created_by": created_by,
        "created_at": _now_iso(),
        "prefired_by": None,
        "prefired_at": None,
        "attack_started_at": None,
        "attack_completed_at": None,
        "packaged_at": None,
        "blue_started_at": None,
        "blue_started_by": None,
    }

    _save_room(room)

    return room



def prefire_room(room_id: str, username: str) -> dict:
    """Mark a room as pre-fired/deferred.

    The actual attack and alert events still arrive through the existing
    red-team/signal/Blue Team event pipelines. This function records the room
    lifecycle gate used by the control plane.
    """
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot prefire a closed room")
    if room.get("blue_started_at"):
        raise RuntimeError("Cannot prefire after the Blue team has started")

    now = _now_iso()
    room.setdefault("exercise_mode", "deferred")
    room["status"] = "packaged"
    room["prefired_by"] = room.get("prefired_by") or username
    room["prefired_at"] = room.get("prefired_at") or now
    room["packaged_at"] = room.get("packaged_at") or now
    _save_room(room)
    return room


def start_blue_team(room_id: str, username: str) -> dict:
    """Start the deferred Blue-team timer when a Blue user launches TheHive."""
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot start a closed room")
    if room.get("exercise_mode", "deferred") == "deferred" and not room.get("packaged_at"):
        raise RuntimeError("Room is not packaged yet")

    members = room.setdefault("blue_team_members", [])
    if username not in members:
        members.append(username)
    if not room.get("blue_started_at"):
        room["blue_started_at"] = _now_iso()
        room["blue_started_by"] = username
    room["status"] = "blue_active"
    room["hive_launch_url"] = os.getenv("THEHIVE_PUBLIC_URL", "http://localhost:9000")
    _save_room(room)
    return room


def record_incident_event(room_id: str, event_type: str, timestamp: str) -> dict:
    """Update room lifecycle timestamps from incident events."""
    room = _load_room(room_id)
    if event_type == "malicious_action_executed":
        room["attack_started_at"] = room.get("attack_started_at") or timestamp
        room["attack_completed_at"] = timestamp
    elif event_type == "alert_raised":
        room["packaged_at"] = room.get("packaged_at") or timestamp
        if room.get("status") in {"created", "prefiring"}:
            room["status"] = "packaged"
    _save_room(room)
    return room


def spin_up_blueteam(room_id: str) -> dict:
    room = _load_room(room_id)
    if room["status"] in {"active", "blue_active"}:
        return room

    soc_manager = next(
        (
            user
            for user in user_store.get_users_by_company(room["company_id"])
            if user.get("role") == "soc_manager"
        ),
        None,
    )
    runtime_keys = user_store.get_blue_team_runtime_keys(soc_manager["id"]) if soc_manager else {}
    hive_api_key = runtime_keys.get("hive_api_key") or (soc_manager or {}).get("hive_key")
    if not soc_manager or not hive_api_key:
        raise RuntimeError(
            f"No SOC manager with a Hive API key found for company {room['company_id']}"
        )

    environment = {
        "INCIDENT_ID": (room.get("incidents") or [room["incident_id"]])[0],
        "HIVE_URL": "http://thehive:9000",
        "HIVE_API_KEY": hive_api_key,
        "SANDBOX_URL": "http://target-agent:80",
    }
    if runtime_keys.get("cortex_api_key"):
        environment["CORTEX_API_KEY"] = runtime_keys["cortex_api_key"]

    client = None
    container = None
    container_name = f"blueteam_{room_id}"
    try:
        client = docker.from_env()
        container = client.containers.run(
            image=BLUETEAM_IMAGE,
            name=container_name,
            environment=environment,
            network=DOCKER_NETWORK,
            detach=True,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            container.reload()
            state = container.attrs.get("State", {})
            health = state.get("Health", {}).get("Status")
            if health == "healthy":
                break
            if state.get("Status") in {"exited", "dead"} or health == "unhealthy":
                raise RuntimeError(
                    f"Blue Team container became {health or state.get('Status')}"
                )
            time.sleep(2)
        else:
            raise RuntimeError("Blue Team container did not become healthy within 90 seconds")
        _configure_signal_store_incident((room.get("incidents") or [room["incident_id"]])[0])
        room["status"] = "active"
        _save_room(room)
    except Exception as exc:
        # Best-effort teardown of whatever container this attempt created.
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                logger.exception(
                    "Failed to force-remove Blue Team container %s during cleanup",
                    container_name,
                )
        # Re-check the container is actually gone; a lingering container keeps
        # room["port"] bound and would block any retry of this room.
        if client is not None:
            try:
                leftover = client.containers.list(all=True, filters={"name": container_name})
            except Exception:
                logger.exception(
                    "Could not verify removal of Blue Team container %s", container_name
                )
            else:
                if leftover:
                    logger.error(
                        "Blue Team container %s still present after force-remove: %s",
                        container_name,
                        [c.id for c in leftover],
                    )
        raise RuntimeError(f"Failed to start Blue Team room {room_id}: {exc}") from exc

    return room


def spin_down_room(room_id: str) -> dict:
    room = _load_room(room_id)

    if room["status"] == "created":
        if room.get("port") is not None:  # Legacy rooms created before ports were internal-only.
            port_pool.release(room["port"])
        room["status"] = "closed"
        _save_room(room)
        return room

    try:
        client = docker.from_env()
        container = client.containers.get(f"blueteam_{room_id}")
        container.stop()
        container.remove()
    except Exception as exc:
        raise RuntimeError(f"Failed to stop Blue Team room {room_id}: {exc}") from exc

    if room.get("port") is not None:  # Legacy rooms created before ports were internal-only.
        port_pool.release(room["port"])
    room["status"] = "closed"
    try:
        _configure_signal_store_incident(None)
    except RuntimeError:
        # The room is already safely closed.  Keep teardown idempotent, but
        # retain a clear operational signal that the mapper needs attention.
        logger.exception("Failed to clear active signal-store incident for room %s", room_id)
    _generate_final_reports(room)
    _save_room(room)
    return room


def _generate_final_reports(room: dict) -> None:
    """On exercise end, run the evaluation pipeline for each of the room's
    incidents, write each markdown report (to /attense/actions/), and store a
    compact scored summary under room["final_reports"] (this is the ERD's
    "Room --generates--> AI report").

    Best-effort by design: wrapped per incident so a scoring/IO failure (or an
    incident with no events to score) is logged and skipped rather than
    blocking room teardown. The room is already stopped/closed at this point.
    """
    reports = []
    for incident_id in (room.get("incidents") or []):
        try:
            from pipeline.run_pipeline import build_and_write_report

            result = build_and_write_report(incident_id)
        except Exception:
            logger.exception(
                "Final report generation failed for incident %s", incident_id
            )
            continue
        if result is None:
            continue
        reports.append({
            "incident_id":    result["incident_id"],
            "final_score":    result["final_score"],
            "verdict":        result["verdict"],
            "outcome":        result["outcome"],
            "report_path":    result["report_path"],
            "member_reports": result.get("member_reports", []),
        })
    if reports:
        room["final_reports"] = reports


def add_incident(room_id: str, incident_id: str) -> dict:
    """Associate an incident with a room (idempotent). Returns the room."""
    room = _load_room(room_id)
    incidents = room.setdefault("incidents", [])
    if incident_id not in incidents:
        incidents.append(incident_id)
        _save_room(room)
    return room



def find_room_for_incident(incident_id: str) -> Optional[dict]:
    """Return the room whose designated/associated incidents include incident_id."""
    if not ROOMS_DIR.exists():
        return None
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            continue
        if room.get("incident_id") == incident_id or incident_id in room.get("incidents", []):
            return room
    return None


def find_room_id_for_incident(incident_id: str) -> Optional[str]:
    """Return the room_id whose designated or associated incidents include
    incident_id, or None if no room matches."""
    room = find_room_for_incident(incident_id)
    return room.get("room_id") if room else None


def join_room_as_red_team(room_id: str, username: str) -> dict:
    """Add username to the room's red_team_members (idempotent). Membership
    is permissive Ã¢â‚¬â€ a red_team user may belong to more than one room; see
    user_store.set_active_room for the most-recently-joined tie-break."""
    room = _load_room(room_id)
    members = room.setdefault("red_team_members", [])
    if username not in members:
        members.append(username)
        _save_room(room)
    return room


def get_room_if_member(room_id: str, username: str) -> Optional[dict]:
    """Return the room if it still exists, isn't closed, and username is
    actually a red_team_members entry Ã¢â‚¬â€ None otherwise. Used to validate a
    user's active_room_id pointer hasn't gone stale (room closed/deleted)."""
    try:
        room = _load_room(room_id)
    except ValueError:
        return None
    if room.get("status") == "closed":
        return None
    if username not in room.get("red_team_members", []):
        return None
    return room


def find_room_for_red_team_member(username: str) -> Optional[dict]:
    """Scan all rooms (mirrors find_room_id_for_incident) for the first
    non-closed room containing username in red_team_members. Fallback used
    when active_room_id is unset or stale."""
    if not ROOMS_DIR.exists():
        return None
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            continue
        if room.get("status") == "closed":
            continue
        if username in room.get("red_team_members", []):
            return room
    return None


def list_rooms_for_company(company_id: Optional[str]) -> list[dict]:
    """Return rooms for company_id, or every room if company_id is None
    (the ciso case Ã¢â‚¬â€ company_id=None means cross-company oversight, not
    'no company', matching how list_pending/confirm already treat ciso)."""
    if not ROOMS_DIR.exists():
        return []
    rooms = []
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            continue
        if company_id is None or room.get("company_id") == company_id:
            rooms.append(room)
    return rooms
