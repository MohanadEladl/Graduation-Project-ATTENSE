"""
XSS variant separation (Part 2 of the lab repair).

Easy = reflected HTML body (xss_reflected_html_executed),
Medium = attribute-context bypass (xss_attribute_context_bypass),
Hard = stored (stored_xss_persisted). Each level's goal event must complete ONLY
its own variant — a reflected payload can no longer complete the stored variant.
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


def _ev(event_type, path, module_id="xss", via="browser", ts=1.0, backend="operator"):
    return {"event_type": event_type, "path": path, "method": "GET", "via": via,
            "ts": ts, "module_id": module_id, "extra": {"backend": backend, "path": path}}


def _run(events, variant_id, monkeypatch, module_id="xss"):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    return lab_progress.compute(module_id, 0.0, mode="lab", variant_id=variant_id)


EASY = _ev("xss_reflected_html_executed", "/op/search")
MEDIUM = _ev("xss_attribute_context_bypass", "/op/search")
HARD = _ev("stored_xss_persisted", "/op/comments")


# ── Easy ────────────────────────────────────────────────────────────────────
def test_easy_payload_completes_easy(monkeypatch):
    assert _run([EASY], "reflected", monkeypatch)["success"] is True


def test_easy_payload_does_not_complete_medium(monkeypatch):
    assert _run([EASY], "alternate_context", monkeypatch)["success"] is False


def test_easy_payload_does_not_complete_hard(monkeypatch):
    assert _run([EASY], "stored_attempt", monkeypatch)["success"] is False


# ── Medium ──────────────────────────────────────────────────────────────────
def test_medium_payload_completes_medium(monkeypatch):
    assert _run([MEDIUM], "alternate_context", monkeypatch)["success"] is True


def test_medium_payload_does_not_complete_easy(monkeypatch):
    assert _run([MEDIUM], "reflected", monkeypatch)["success"] is False


def test_medium_payload_does_not_complete_hard(monkeypatch):
    assert _run([MEDIUM], "stored_attempt", monkeypatch)["success"] is False


# ── Hard ────────────────────────────────────────────────────────────────────
def test_hard_stored_completes_hard(monkeypatch):
    assert _run([HARD], "stored_attempt", monkeypatch)["success"] is True


def test_hard_not_completed_by_reflected_only(monkeypatch):
    # Reflected + attribute evidence must NOT complete the stored variant.
    r = _run([EASY, MEDIUM], "stored_attempt", monkeypatch)
    assert r["success"] is False


def test_hard_reflected_does_not_leak_into_hard(monkeypatch):
    assert _run([_ev("xss_reflected_html_executed", "/op/search")], "stored_attempt", monkeypatch)["success"] is False


# ── Trigger event identity ────────────────────────────────────────────────────
def test_trigger_event_is_variant_specific(monkeypatch):
    assert _run([EASY], "reflected", monkeypatch)["trigger_event"] == "xss_reflected_html_executed"
    assert _run([MEDIUM], "alternate_context", monkeypatch)["trigger_event"] == "xss_attribute_context_bypass"
    assert _run([HARD], "stored_attempt", monkeypatch)["trigger_event"] == "stored_xss_persisted"
