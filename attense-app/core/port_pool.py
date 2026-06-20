import logging
import threading

import docker

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()


def _ports_in_use() -> set[int]:
    """Host ports already bound by running blueteam_* room containers, so a
    process restart doesn't hand out a port a still-running room already holds."""
    try:
        client = docker.from_env()
        containers = client.containers.list(filters={"name": "blueteam_"})
    except Exception:
        logger.warning("port_pool: docker client unavailable, falling back to full port range")
        return set()

    in_use = set()
    for container in containers:
        for bindings in (container.ports or {}).values():
            for binding in bindings or []:
                host_port = binding.get("HostPort")
                if host_port:
                    in_use.add(int(host_port))
    return in_use


_RESERVED_PORTS = _ports_in_use()
_FREE_PORTS = [port for port in range(8110, 8131) if port not in _RESERVED_PORTS]


def acquire() -> int:
    with _LOCK:
        if not _FREE_PORTS:
            raise RuntimeError("No free ports available in pool")
        return _FREE_PORTS.pop(0)


def release(port: int) -> None:
    with _LOCK:
        _FREE_PORTS.append(port)
