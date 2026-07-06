"""
Command Injection variant separation (Part 4 of the lab repair).

Easy = semicolon (cmd_injection_semicolon_success),
Medium = pipe/redirect (cmd_injection_pipe_success),
Hard = subshell (cmd_injection_subshell_success). Each level's goal event
completes ONLY its own variant.
"""
import sys
import types
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

if "docker" not in sys.modules:
    docker_stub = types.ModuleType("docker")
    docker_error = type("DockerException", (Exception,), {})
    docker_stub.from_env = lambda: None
    docker_stub.errors = types.SimpleNamespace(
        DockerException=docker_error, NotFound=docker_error, APIError=docker_error,
    )
    sys.modules["docker"] = docker_stub

from backend import lab_progress  # noqa: E402


def _ev(event_type, via="browser", ts=1.0):
    return {"event_type": event_type, "path": "/op/system/ping", "method": "GET",
            "via": via, "ts": ts, "module_id": "cmd_injection",
            "extra": {"backend": "operator", "path": "/op/system/ping"}}


def _run(events, variant_id, monkeypatch):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    return lab_progress.compute("cmd_injection", 0.0, mode="lab", variant_id=variant_id)


EASY = _ev("cmd_injection_semicolon_success")
MED = _ev("cmd_injection_pipe_success")
HARD = _ev("cmd_injection_subshell_success")


def test_semicolon_completes_easy_only(monkeypatch):
    assert _run([EASY], "semicolon_basic", monkeypatch)["success"] is True
    assert _run([EASY], "pipe_redirect", monkeypatch)["success"] is False
    assert _run([EASY], "subshell", monkeypatch)["success"] is False


def test_pipe_completes_medium_only(monkeypatch):
    assert _run([MED], "pipe_redirect", monkeypatch)["success"] is True
    assert _run([MED], "semicolon_basic", monkeypatch)["success"] is False
    assert _run([MED], "subshell", monkeypatch)["success"] is False


def test_subshell_completes_hard_only(monkeypatch):
    assert _run([HARD], "subshell", monkeypatch)["success"] is True
    assert _run([HARD], "semicolon_basic", monkeypatch)["success"] is False
    assert _run([HARD], "pipe_redirect", monkeypatch)["success"] is False


def test_separator_observed_alone_does_not_complete(monkeypatch):
    # The attempt marker must not complete any variant.
    attempt = _ev("command_separator_observed")
    assert _run([attempt], "semicolon_basic", monkeypatch)["success"] is False


def test_trigger_events_are_variant_specific(monkeypatch):
    assert _run([EASY], "semicolon_basic", monkeypatch)["trigger_event"] == "cmd_injection_semicolon_success"
    assert _run([MED], "pipe_redirect", monkeypatch)["trigger_event"] == "cmd_injection_pipe_success"
    assert _run([HARD], "subshell", monkeypatch)["trigger_event"] == "cmd_injection_subshell_success"
