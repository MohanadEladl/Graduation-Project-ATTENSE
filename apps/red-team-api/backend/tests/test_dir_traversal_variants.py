"""
Directory Traversal variant separation (Part 5 of the lab repair).

Easy = plain ../ (traversal_plain_success),
Medium = URL-encoded (traversal_encoded_success),
Hard = absolute path (traversal_absolute_bypass_success). Each level's goal
event completes ONLY its own variant.
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
    return {"event_type": event_type, "path": "/op/files/read", "method": "GET",
            "via": via, "ts": ts, "module_id": "dir_traversal",
            "extra": {"backend": "operator", "path": "/op/files/read"}}


def _run(events, variant_id, monkeypatch):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    return lab_progress.compute("dir_traversal", 0.0, mode="lab", variant_id=variant_id)


PLAIN = _ev("traversal_plain_success")
ENC = _ev("traversal_encoded_success")
ABS = _ev("traversal_absolute_bypass_success")


def test_plain_completes_easy_only(monkeypatch):
    assert _run([PLAIN], "plain", monkeypatch)["success"] is True
    assert _run([PLAIN], "encoded", monkeypatch)["success"] is False
    assert _run([PLAIN], "absolute", monkeypatch)["success"] is False


def test_encoded_completes_medium_only(monkeypatch):
    assert _run([ENC], "encoded", monkeypatch)["success"] is True
    assert _run([ENC], "plain", monkeypatch)["success"] is False
    assert _run([ENC], "absolute", monkeypatch)["success"] is False


def test_absolute_completes_hard_only(monkeypatch):
    assert _run([ABS], "absolute", monkeypatch)["success"] is True
    assert _run([ABS], "plain", monkeypatch)["success"] is False
    assert _run([ABS], "encoded", monkeypatch)["success"] is False


def test_pattern_observed_alone_does_not_complete(monkeypatch):
    assert _run([_ev("traversal_pattern_observed")], "plain", monkeypatch)["success"] is False


def test_trigger_events_are_variant_specific(monkeypatch):
    assert _run([PLAIN], "plain", monkeypatch)["trigger_event"] == "traversal_plain_success"
    assert _run([ENC], "encoded", monkeypatch)["trigger_event"] == "traversal_encoded_success"
    assert _run([ABS], "absolute", monkeypatch)["trigger_event"] == "traversal_absolute_bypass_success"
