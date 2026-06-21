import json
import logging
import os
import threading
from pathlib import Path

import docker

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()

_PORT_RANGE = range(8110, 8131)

TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
ROOMS_DIR = Path(TEMP_PATH) / "rooms"

# Rooms in these states no longer hold their port reservation.
_TERMINAL_ROOM_STATES = {"closed"}


def _ports_reserved_by_rooms() -> set[int]:
    """Host ports reserved by persisted rooms that are not in a terminal state.

    The room files are the authoritative reservation ledger: a port is acquired
    at room creation and persisted *before* any container exists, so a room in
    the ``created`` state holds a port with no container behind it. Reconciling
    only against running containers would free those ports and let a second room
    acquire one already promised to the first."""
    if not ROOMS_DIR.exists():
        return set()

    reserved = set()
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            # A corrupt/unreadable room file is exactly when we must be
            # conservative: skip it here, but running-container reconciliation
            # below still protects any port it had actually bound.
            continue
        if room.get("status") in _TERMINAL_ROOM_STATES:
            continue
        port = room.get("port")
        if isinstance(port, int):
            reserved.add(port)
    return reserved


def _ports_bound_by_containers() -> set[int]:
    """Host ports already bound by running blueteam_* containers. Backstop for
    the room-file ledger in case a file is missing or corrupt."""
    try:
        client = docker.from_env()
        containers = client.containers.list(filters={"name": "blueteam_"})
    except Exception:
        logger.warning("port_pool: docker client unavailable, relying on room ledger only")
        return set()

    in_use = set()
    for container in containers:
        for bindings in (container.ports or {}).values():
            for binding in bindings or []:
                host_port = binding.get("HostPort")
                if host_port:
                    in_use.add(int(host_port))
    return in_use


def _reserved_ports() -> set[int]:
    return _ports_reserved_by_rooms() | _ports_bound_by_containers()


_RESERVED_PORTS = _reserved_ports()
_FREE_PORTS = [port for port in _PORT_RANGE if port not in _RESERVED_PORTS]


def acquire() -> int:
    with _LOCK:
        if not _FREE_PORTS:
            raise RuntimeError("No free ports available in pool")
        return _FREE_PORTS.pop(0)


def release(port: int) -> None:
    with _LOCK:
        # Idempotent: a double release (e.g. spin_down called twice) must not
        # plant a duplicate that acquire() would later hand to two rooms.
        if port in _PORT_RANGE and port not in _FREE_PORTS:
            _FREE_PORTS.append(port)
