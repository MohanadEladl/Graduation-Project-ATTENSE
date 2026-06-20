import json
import os
import uuid
from pathlib import Path

import docker

from core import port_pool, user_store


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
    # scenario_id identifies the requested scenario but is not part of the room schema.
    _ = scenario_id
    room_id = str(uuid.uuid4())
    incident_id = str(uuid.uuid4())
    port = port_pool.acquire()

    room = {
        "room_id": room_id,
        "company_id": company_id,
        "incident_id": incident_id,
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

    try:
        client = docker.from_env()
        client.containers.run(
            image=BLUETEAM_IMAGE,
            name=f"blueteam_{room_id}",
            environment={
                "INCIDENT_ID": room["incident_id"],
                "HIVE_URL": "http://thehive:9000",
                "HIVE_API_KEY": soc_manager["hive_key"],
                "SANDBOX_URL": "http://target-agent:80",
            },
            ports={"8010/tcp": room["port"]},
            network=DOCKER_NETWORK,
            detach=True,
        )
        room["status"] = "active"
        _save_room(room)
    except Exception as exc:
        raise RuntimeError(f"Failed to start Blue Team room {room_id}: {exc}") from exc

    return room


def spin_down_room(room_id: str) -> dict:
    room = _load_room(room_id)

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
