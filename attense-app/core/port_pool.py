import threading

_LOCK = threading.Lock()
_FREE_PORTS = list(range(8110, 8131))


def acquire() -> int:
    with _LOCK:
        if not _FREE_PORTS:
            raise RuntimeError("No free ports available in pool")
        return _FREE_PORTS.pop(0)


def release(port: int) -> None:
    with _LOCK:
        _FREE_PORTS.append(port)
