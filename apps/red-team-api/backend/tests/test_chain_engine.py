"""
Chain-engine (Gauntlet) advancement tests.

The authoritative Red Team completion model is goal-trigger based: a phase is
COMPLETE the instant its goal event fires on the operator target, regardless of
the legacy `progress_percent` task-ladder value (which stays 25–33% for a
single goal event). The Gauntlet must advance on that signal, not on
`progress_percent >= threshold`.
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

from backend import chain_engine, lab_progress  # noqa: E402


def _recon_goal_event():
    """A single recon goal event: goal_triggered=True but progress_percent<60.

    ts is far in the future so it always lands after the chain's started_at
    (compute() filters events older than mission_started_at).
    """
    return [{
        "event_type": "recon_sequence_observed",
        "path": "/op/", "method": "GET", "via": "attackbox", "ts": 9_999_999_999.0,
        "extra": {"backend": "operator", "path": "/op/"},
    }]


def _patch_events(monkeypatch, events):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)


def test_check_step_complete_uses_goal_trigger_not_progress_percent(monkeypatch):
    """A single goal event (progress_percent 25–33) must satisfy the phase."""
    _patch_events(monkeypatch, _recon_goal_event())
    started = chain_engine.start_chain("full_compromise", "sess-1")
    csid = started["id"]

    # Sanity: this event genuinely triggers the goal while leaving low progress%.
    result = lab_progress.compute("recon", 0.0, mode="lab", variant_id=None)
    assert result["goal_triggered"] is True
    assert result["progress_percent"] < 60

    assert chain_engine.check_step_complete(csid) is True


def test_advance_chain_on_goal_trigger_stores_goal_fields(monkeypatch):
    """advance_chain must advance on the goal and record goal-trigger fields."""
    _patch_events(monkeypatch, _recon_goal_event())
    # Don't hit the network when resetting evidence.
    monkeypatch.setattr(chain_engine, "_reset_evidence", lambda: None, raising=False)

    started = chain_engine.start_chain("full_compromise", "sess-2")
    csid = started["id"]

    updated = chain_engine.advance_chain(csid)
    assert updated["current_step_index"] == 1

    phase = updated["phase_results"][0]
    assert phase["passed"] is True
    assert phase["goal_triggered"] is True
    assert phase["trigger_event"] == "recon_sequence_observed"


def test_incomplete_phase_does_not_advance(monkeypatch):
    """No goal event → phase stays put and advance_chain refuses."""
    _patch_events(monkeypatch, [])
    started = chain_engine.start_chain("full_compromise", "sess-3")
    csid = started["id"]

    assert chain_engine.check_step_complete(csid) is False
    import pytest
    with pytest.raises(ValueError):
        chain_engine.advance_chain(csid)
