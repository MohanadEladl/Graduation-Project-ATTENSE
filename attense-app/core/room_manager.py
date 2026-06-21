import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

import docker

from core import company_store, port_pool, user_store

logger = logging.getLogger(__name__)


TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
ROOMS_DIR = Path(TEMP_PATH) / "rooms"
BLUETEAM_IMAGE = "attense-app-blueteam"
DOCKER_NETWORK = "attense_net"


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


def create_room(company_id: str, scenario_id: str, created_by: str) -> dict:
    company = company_store.get_company(company_id)
    if company is None:
        raise ValueError(f"Company not found: {company_id}")
    if company["status"] != "active":
        raise RuntimeError("Company must be confirmed before creating rooms")
    room_id = str(uuid.uuid4())
    incident_id = str(uuid.uuid4())
    port = port_pool.acquire()

    room = {
        "room_id": room_id,
        "company_id": company_id,
        "incident_id": incident_id,
        "incidents": [incident_id],
        "scenario_id": scenario_id,
        "port": port,
        "status": "created",
        "blue_team_members": [],
        "red_team_members": [],
        "created_by": created_by,
    }

    try:
        _save_room(room)
    except Exception:
        port_pool.release(port)
        raise

    return room


def spin_up_blueteam(room_id: str) -> dict:
    room = _load_room(room_id)
    if room["status"] == "active":
        return room

    soc_manager = next(
        (
            user
            for user in user_store.get_users_by_company(room["company_id"])
            if user.get("role") == "soc_manager"
        ),
        None,
    )
    if not soc_manager or not soc_manager.get("hive_key"):
        raise RuntimeError(
            f"No SOC manager with a Hive API key found for company {room['company_id']}"
        )

    client = None
    container = None
    container_name = f"blueteam_{room_id}"
    try:
        client = docker.from_env()
        container = client.containers.run(
            image=BLUETEAM_IMAGE,
            name=container_name,
            environment={
                "INCIDENT_ID": (room.get("incidents") or [room["incident_id"]])[0],
                "HIVE_URL": "http://thehive:9000",
                "HIVE_API_KEY": soc_manager["hive_key"],
                "SANDBOX_URL": "http://target-agent:80",
            },
            ports={"8010/tcp": room["port"]},
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
        # No port_pool.release() here: the port was acquired in create_room and
        # is still owned by this room (status stays "created"). Releasing it
        # would let another room acquire a port this room's file still claims.
        # The port is freed only by spin_down_room.
        raise RuntimeError(f"Failed to start Blue Team room {room_id}: {exc}") from exc

    return room


def spin_down_room(room_id: str) -> dict:
    room = _load_room(room_id)

    if room["status"] == "created":
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

    port_pool.release(room["port"])
    room["status"] = "closed"
    _save_room(room)
    return room


def add_incident(room_id: str, incident_id: str) -> dict:
    """Associate an incident with a room (idempotent). Returns the room."""
    room = _load_room(room_id)
    incidents = room.setdefault("incidents", [])
    if incident_id not in incidents:
        incidents.append(incident_id)
        _save_room(room)
    return room


def find_room_id_for_incident(incident_id: str) -> Optional[str]:
    """Return the room_id whose designated or associated incidents include
    incident_id, or None if no room matches."""
    if not ROOMS_DIR.exists():
        return None
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            continue
        if room.get("incident_id") == incident_id or incident_id in room.get("incidents", []):
            return room.get("room_id")
    return None
