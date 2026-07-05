"""
Per-module operator goal-trigger gating tests.

The Red Team completion model is a GOAL-TRIGGER engine (see lab_progress.GOAL_TRIGGERS):

  Lab / Operator mode — a mission completes the instant its goal event is
  observed on the operator target (backend=operator, /op/* path or a derived
  operator event, matching module). Completion is via-INDEPENDENT: Browser,
  AttackBox, ZAP Repeater/Fuzzer, curl, and even an uncaptured via="unknown"
  all complete the mission. Tool choice only shapes the quality score/report,
  never completion. Guided-surface (backend != operator) and wrong-module
  evidence still never complete.

  Tutorial / Guided mode — READING-ONLY. compute() short-circuits to a static
  reading_only response before any event is fetched, so success is always
  False regardless of evidence — see test_guided_reading_only.py.
"""
import sys
import types
from pathlib import Path

import pytest

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


GATED_MODULES = ["recon", "xss", "cmd_injection", "dir_traversal", "file_upload", "csrf"]
APPROVED_TOOLS = ["attackbox", "zap_repeater", "zap_fuzzer"]
# Every local channel now completes a real goal — tools AND browser AND unknown.
ALL_LOCAL_VIA = APPROVED_TOOLS + ["browser", "unknown"]

# Canonical operator + guided route for each module's goal event.
OP_PATH = {
    "recon":         "/op/",
    "xss":           "/op/search",
    "cmd_injection": "/op/system/ping",
    "dir_traversal": "/op/files/read",
    "file_upload":   "/op/files/upload",
    "csrf":          "/op/profile/update",
}
GUIDED_PATH = {
    "recon":         "/",
    "xss":           "/search",
    "cmd_injection": "/system/ping",
    "dir_traversal": "/files/read",
    "file_upload":   "/files/upload",
    "csrf":          "/profile/update",
}


def _goal_types(module_id):
    """One representative goal event type that completes the module."""
    return list(lab_progress.completion_event_types(module_id))


def _events(module_id, *, path, backend, via):
    """Build one goal event, tagged with the given channel."""
    return [
        {
            "event_type": t,
            "path": path,
            "method": "GET",
            "via": via,
            "ts": float(i + 1),
            "module_id": module_id,
            "extra": {"backend": backend, "path": path},
        }
        for i, t in enumerate(_goal_types(module_id))
    ]


def _patch(monkeypatch, events):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)


# ── Lab / Operator mode — goal event completes via ANY local channel ─────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
@pytest.mark.parametrize("via", ALL_LOCAL_VIA)
def test_operator_goal_completes_via_any_local_channel(monkeypatch, module_id, via):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via=via)
    _patch(monkeypatch, events)
    r = lab_progress.compute(module_id, 0.0, mode="lab")
    assert r["success"] is True, f"{module_id} via {via} should complete"
    assert r["goal_triggered"] is True
    assert r["status"] == "complete"


# ── Quality still depends on tool channel (report-only, never blocks) ────────
def test_tool_channel_scores_higher_quality_than_browser(monkeypatch):
    tool = _events("cmd_injection", path=OP_PATH["cmd_injection"], backend="operator", via="zap_repeater")
    _patch(monkeypatch, tool)
    q_tool = lab_progress.compute("cmd_injection", 0.0, mode="lab")["quality_score"]

    browser = _events("cmd_injection", path=OP_PATH["cmd_injection"], backend="operator", via="browser")
    _patch(monkeypatch, browser)
    r_browser = lab_progress.compute("cmd_injection", 0.0, mode="lab")
    assert r_browser["success"] is True
    assert r_browser["quality_score"] <= q_tool


def test_unknown_channel_completes_but_reports_unstructured_method(monkeypatch):
    events = _events("xss", path=OP_PATH["xss"], backend="operator", via="unknown")
    _patch(monkeypatch, events)
    r = lab_progress.compute("xss", 0.0, mode="lab")
    assert r["success"] is True
    assert any("not captured" in t or "unstructured" in t for t in r["observed_tools"])


# ── Safety: guided surface never completes an operator mission ───────────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_guided_surface_does_not_complete_operator(monkeypatch, module_id):
    # Right goal event, but the request hit the GUIDED surface (backend != operator).
    events = _events(module_id, path=GUIDED_PATH[module_id], backend="guided", via="zap_repeater")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


# ── Safety: wrong module tag never completes another module ──────────────────
def test_wrong_module_tag_does_not_complete(monkeypatch):
    # xss goal event, but tagged module_id=recon.
    events = [{
        "event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
        "via": "zap_repeater", "ts": 1.0, "module_id": "recon",
        "extra": {"backend": "operator", "path": "/op/search"},
    }]
    _patch(monkeypatch, events)
    assert lab_progress.compute("xss", 0.0, mode="lab")["success"] is False


# ── Safety: a random unrelated event never completes ─────────────────────────
def test_random_unrelated_event_does_not_complete(monkeypatch):
    events = [{
        "event_type": "portal_visited", "path": "/op/", "method": "GET",
        "via": "browser", "ts": 1.0, "module_id": "xss",
        "extra": {"backend": "operator", "path": "/op/"},
    }]
    _patch(monkeypatch, events)
    assert lab_progress.compute("xss", 0.0, mode="lab")["success"] is False


# ── Tutorial / Guided mode — reading-only, regardless of evidence ────────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_tutorial_never_completes_even_with_operator_evidence(monkeypatch, module_id):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via="zap_repeater")
    _patch(monkeypatch, events)
    result = lab_progress.compute(module_id, 0.0, mode="tutorial")
    assert result["success"] is False
    assert result["reading_only"] is True
    assert result["goal_triggered"] is False


# ── Evidence timeline: goal event counts for completion regardless of via ────
@pytest.mark.parametrize("via", ALL_LOCAL_VIA)
def test_goal_event_counts_for_completion_any_via(monkeypatch, via):
    events = _events("xss", path="/op/search", backend="operator", via=via)
    _patch(monkeypatch, events)
    result = lab_progress.compute("xss", 0.0, mode="lab")
    assert result["evidence"], "goal proof must be visible as cards"
    assert all(card["counts_for_completion"] is True for card in result["evidence"])


def test_browser_goal_counts_for_completion_not_quality(monkeypatch):
    events = _events("xss", path="/op/search", backend="operator", via="browser")
    _patch(monkeypatch, events)
    result = lab_progress.compute("xss", 0.0, mode="lab")
    assert all(card["counts_for_completion"] is True for card in result["evidence"])
    assert all(card["counts_for_quality"] is False for card in result["evidence"])
