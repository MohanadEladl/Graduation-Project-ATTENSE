"""Runtime containment state and constrained enforcement helpers."""

from __future__ import annotations

import json
import os
import signal
import threading
from pathlib import Path


STATE_PATH = Path(os.getenv("CONTAINMENT_STATE_PATH", "/app/runtime/containment_state.json"))
UPLOAD_DIR = Path("/app/static/uploads").resolve()
_LOCK = threading.RLock()
_DEFAULT_STATE = {
    "sanitize_input": False,
    "blocked_paths": [],
    "csrf_protection": False,
}


def _load() -> dict:
    with _LOCK:
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            data = {}
        return {**_DEFAULT_STATE, **data}


def _save(state: dict) -> None:
    with _LOCK:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp_path = STATE_PATH.with_suffix(".tmp")
        temp_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(temp_path, STATE_PATH)


def enable(action: str, target: str | None = None) -> dict:
    state = _load()
    if action == "sanitize_input":
        state["sanitize_input"] = True
    elif action == "block_path":
        normalized = (target or "").strip()
        if not normalized:
            raise ValueError("block_path requires a path observable")
        if normalized not in state["blocked_paths"]:
            state["blocked_paths"].append(normalized)
    elif action == "enable_csrf_protection":
        state["csrf_protection"] = True
    else:
        raise ValueError(f"Unsupported state action: {action}")
    _save(state)
    return state


def is_enabled(action: str) -> bool:
    return bool(_load().get(action))


def path_is_blocked(path: str) -> bool:
    state = _load()
    value = (path or "").strip()
    lowered = value.lower()
    traversal = (
        ".." in value
        or "%2e%2e" in lowered
        or value.startswith(("/etc/", "/proc/", "/sys/"))
    )
    blocked_paths = state["blocked_paths"]
    return value in blocked_paths or (bool(blocked_paths) and traversal)


def remove_uploaded_file(filename: str) -> Path:
    name = (filename or "").strip()
    if not name:
        raise ValueError("remove_file requires a filename observable")

    candidate = (UPLOAD_DIR / name).resolve()
    try:
        candidate.relative_to(UPLOAD_DIR)
    except ValueError as exc:
        raise ValueError("File must be inside the upload directory") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"Uploaded file not found: {name}")
    candidate.unlink()
    return candidate


def kill_process(pid_value: str) -> dict:
    try:
        pid = int((pid_value or "").strip())
    except ValueError as exc:
        raise ValueError("kill_process requires a numeric PID observable") from exc
    if pid <= 1 or pid == os.getpid():
        raise ValueError("Refusing to terminate a protected process")

    proc_path = Path(f"/proc/{pid}")
    if not proc_path.is_dir():
        raise ProcessLookupError(f"Process not found: {pid}")
    ancestor = pid
    flask_pid = os.getpid()
    while ancestor > 1 and ancestor != flask_pid:
        try:
            status = Path(f"/proc/{ancestor}/status").read_text(encoding="utf-8")
            ppid_line = next(line for line in status.splitlines() if line.startswith("PPid:"))
            ancestor = int(ppid_line.split(":", 1)[1].strip())
        except (FileNotFoundError, StopIteration, ValueError, OSError):
            break
    if ancestor != flask_pid:
        raise PermissionError("PID is not a child of the target application")
    try:
        command = (proc_path / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
            "utf-8", errors="replace"
        ).strip()
    except OSError:
        command = ""
    os.kill(pid, signal.SIGTERM)
    return {"pid": pid, "command": command}


def snapshot() -> dict:
    return _load()
