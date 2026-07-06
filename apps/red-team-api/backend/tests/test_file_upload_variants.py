"""
File Upload variant separation (Part 6 of the lab repair).

Easy = obvious dangerous ext (upload_basic_dangerous_ext_success),
Medium = extension bypass (upload_extension_bypass_success),
Hard = polyglot / MIME (upload_polyglot_success). Each level's goal event
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
    return {"event_type": event_type, "path": "/op/files/upload", "method": "POST",
            "via": via, "ts": ts, "module_id": "file_upload",
            "extra": {"backend": "operator", "path": "/op/files/upload"}}


def _run(events, variant_id, monkeypatch):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    return lab_progress.compute("file_upload", 0.0, mode="lab", variant_id=variant_id)


EASY = _ev("upload_basic_dangerous_ext_success")
MED = _ev("upload_extension_bypass_success")
HARD = _ev("upload_polyglot_success")


def test_basic_ext_completes_easy_only(monkeypatch):
    assert _run([EASY], "wrong_extension", monkeypatch)["success"] is True
    assert _run([EASY], "mime_spoof", monkeypatch)["success"] is False
    assert _run([EASY], "polyglot", monkeypatch)["success"] is False


def test_ext_bypass_completes_medium_only(monkeypatch):
    assert _run([MED], "mime_spoof", monkeypatch)["success"] is True
    assert _run([MED], "wrong_extension", monkeypatch)["success"] is False
    assert _run([MED], "polyglot", monkeypatch)["success"] is False


def test_polyglot_completes_hard_only(monkeypatch):
    assert _run([HARD], "polyglot", monkeypatch)["success"] is True
    assert _run([HARD], "wrong_extension", monkeypatch)["success"] is False
    assert _run([HARD], "mime_spoof", monkeypatch)["success"] is False


def test_file_saved_alone_does_not_complete(monkeypatch):
    assert _run([_ev("file_saved")], "wrong_extension", monkeypatch)["success"] is False


def test_trigger_events_are_variant_specific(monkeypatch):
    assert _run([EASY], "wrong_extension", monkeypatch)["trigger_event"] == "upload_basic_dangerous_ext_success"
    assert _run([MED], "mime_spoof", monkeypatch)["trigger_event"] == "upload_extension_bypass_success"
    assert _run([HARD], "polyglot", monkeypatch)["trigger_event"] == "upload_polyglot_success"
