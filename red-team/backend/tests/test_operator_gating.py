"""
Per-module operator/guided evidence-gating tests.

These prove that the brute-force operator contract now applies UNIFORMLY to
every other Red Team module (recon, xss, cmd_injection, dir_traversal,
file_upload, csrf) via lab_progress._event_counts_for_mode:

  Lab / Operator mode — an event only completes the mission when it hit the
  /op/ operator surface (backend=operator) through an approved local tool
  (attackbox / zap_repeater / zap_fuzzer). Browser-only and via=unknown traffic
  is visible but never completes. Guided-surface evidence never completes
  operator mode.

  Tutorial / Guided mode — guided-surface evidence from any channel completes;
  operator-surface events do NOT (the two modes never cross-complete).

brute_force is covered separately in test_student_safety.py (it keeps its
dedicated failure-count logic) and is intentionally excluded here.
"""
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "red-team"))

if "docker" not in sys.modules:
    docker_stub = types.ModuleType("docker")
    docker_error = type("DockerException", (Exception,), {})
    docker_stub.from_env = lambda: None
    docker_stub.errors = types.SimpleNamespace(
        DockerException=docker_error, NotFound=docker_error, APIError=docker_error,
    )
    sys.modules["docker"] = docker_stub

from backend import lab_progress  # noqa: E402


# Modules that now share the generalized operator contract (NOT brute_force).
GATED_MODULES = ["recon", "xss", "cmd_injection", "dir_traversal", "file_upload", "csrf"]
APPROVED_TOOLS = ["attackbox", "zap_repeater", "zap_fuzzer"]

# Canonical operator + guided route for each module's success events.
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


def _success_types(module_id):
    """The minimum event types that prove the objective (one per completion
    group) under the objective-based model."""
    return list(lab_progress.completion_event_types(module_id))


def _events(module_id, *, path, backend, via):
    """Build one gated event per success type, tagged with the given channel."""
    return [
        {
            "event_type": t,
            "path": path,
            "method": "GET",
            "via": via,
            "ts": float(i + 1),
            "extra": {"backend": backend, "path": path},
        }
        for i, t in enumerate(_success_types(module_id))
    ]


def _patch(monkeypatch, events):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)


# ── Lab / Operator mode ──────────────────────────────────────────────────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
@pytest.mark.parametrize("via", APPROVED_TOOLS)
def test_operator_completes_via_each_approved_tool(monkeypatch, module_id, via):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via=via)
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is True


@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_operator_browser_only_does_not_complete(monkeypatch, module_id):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via="browser")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_operator_unknown_via_does_not_complete(monkeypatch, module_id):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via="unknown")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_guided_surface_does_not_complete_operator(monkeypatch, module_id):
    # Right tool, but the request hit the GUIDED surface (backend != operator).
    events = _events(module_id, path=GUIDED_PATH[module_id], backend="guided", via="zap_repeater")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


# ── Tutorial / Guided mode ───────────────────────────────────────────────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_tutorial_completes_with_guided_browser_evidence(monkeypatch, module_id):
    events = _events(module_id, path=GUIDED_PATH[module_id], backend="guided", via="browser")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="tutorial")["success"] is True


@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_tutorial_not_completed_by_operator_events(monkeypatch, module_id):
    # Operator-surface evidence must not cross-complete the tutorial mission.
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via="zap_repeater")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="tutorial")["success"] is False


# ── Evidence-card `counts` flag mirrors the gate ─────────────────────────────
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_browser_operator_evidence_is_visible_but_not_counted(monkeypatch, module_id):
    events = _events(module_id, path=OP_PATH[module_id], backend="operator", via="browser")
    _patch(monkeypatch, events)
    result = lab_progress.compute(module_id, 0.0, mode="lab")
    assert result["evidence"], "browser operator traffic must still be visible as cards"
    assert all(card["counts"] is False for card in result["evidence"])
