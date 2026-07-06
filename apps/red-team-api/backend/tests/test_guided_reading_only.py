"""
Guided Mode is reading-only (Part 9.A / product decision: "Guided Mode is no
longer an easy version of the lab"). These tests prove the ENTIRE contract:

  * lab_progress.compute(mode="tutorial"/"guided") always returns
    reading_only=True, success=False, zero scores, empty task/evidence lists —
    regardless of what evidence exists (guided-surface, operator-surface, or
    none at all). No event fetching happens for Guided Mode.
  * session_manager.SessionManager.execute() refuses to run scripted attack
    execution for a guided-mode session, even when the instructor/demo
    auto-attacks flag is enabled.
  * report_agent.generate() refuses to synthesize an attack report for a
    guided-mode session (defense-in-depth; main.py's /report endpoint already
    intercepts this before calling generate()).

Operator Mode regression coverage (Part 9.B/C) lives in
test_operator_gating.py / test_objective_progress.py / test_student_safety.py
and is unaffected by this change — those suites still pass unmodified except
for the two tests that asserted the now-removed guided-completion behavior
(renamed in test_operator_gating.py to prove reading-only instead).
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

from backend import lab_progress, report_agent, session_manager  # noqa: E402

ALL_MODULES = ["recon", "brute_force", "xss", "cmd_injection", "dir_traversal", "file_upload", "csrf"]

API_FIELDS = [
    "success", "reading_only", "objective", "completion_score", "quality_score",
    "completed_required", "completed_quality", "missing_quality", "warnings",
    "next_recommended_action", "tasks", "objective_tasks",
    "raw_event_count", "counted_event_count", "ignored_event_count",
    "ignored_reasons", "last_observed_events", "last_counted_events",
    "evidence", "progress_percent", "completed_tasks", "score",
]


def _patch(monkeypatch, events):
    """Guided Mode must not even call fetch_events — if it does, this
    sentinel makes the test fail loudly instead of silently passing."""
    def _boom(**kwargs):
        raise AssertionError("Guided Mode must not fetch target-agent events")
    monkeypatch.setattr(lab_progress, "fetch_events", _boom if events is None else (lambda **k: events))


# ── A. Reading-only contract holds for every module, in every scenario ──────
@pytest.mark.parametrize("module_id", ALL_MODULES)
@pytest.mark.parametrize("wire_mode", ["tutorial", "guided"])
def test_guided_mode_is_always_reading_only(monkeypatch, module_id, wire_mode):
    _patch(monkeypatch, None)  # fetch_events must never be called
    r = lab_progress.compute(module_id, 0.0, mode=wire_mode)
    assert r["reading_only"] is True
    assert r["success"] is False
    assert r["score"] == 0
    assert r["completion_score"] == 0
    assert r["quality_score"] == 0
    assert r["tasks"] == []
    assert r["objective_tasks"] == []
    assert r["evidence"] == []
    assert r["completed_required"] == []
    assert r["completed_quality"] == []
    assert r["raw_event_count"] == 0
    assert r["counted_event_count"] == 0
    assert "Operator Mode" in r["next_recommended_action"]
    assert any("reading-only" in w.lower() for w in r["warnings"])


def test_reading_only_progress_public_alias_matches_compute():
    """reading_only_progress() is the stable, non-underscored entry point the
    product spec names directly; it must return the exact same contract."""
    via_alias = lab_progress.reading_only_progress("xss")
    via_compute = lab_progress.compute("xss", 0.0, mode="guided")
    # Same keys, same static values (compute() adds nothing dynamic for guided).
    assert via_alias.keys() == via_compute.keys()
    for key in via_alias:
        assert via_alias[key] == via_compute[key], f"mismatch on {key!r}"


@pytest.mark.parametrize("module_id", ALL_MODULES)
def test_compute_returns_full_api_shape_for_guided_mode(monkeypatch, module_id):
    _patch(monkeypatch, None)
    r = lab_progress.compute(module_id, 0.0, mode="tutorial")
    for field in API_FIELDS:
        assert field in r, f"{module_id}: guided response missing {field!r}"
    for bucket in lab_progress.IGNORED_REASONS:
        assert r["ignored_reasons"][bucket] == 0


def test_guided_mode_never_fetches_events(monkeypatch):
    """Explicit standalone assertion of the no-event-fetch guarantee."""
    called = {"n": 0}

    def _spy(**kwargs):
        called["n"] += 1
        return []
    monkeypatch.setattr(lab_progress, "fetch_events", _spy)
    lab_progress.compute("xss", 0.0, mode="tutorial")
    assert called["n"] == 0, "compute() must short-circuit before calling fetch_events"


# ── Evidence presence never changes the outcome ─────────────────────────────
def test_guided_mode_ignores_operator_and_guided_evidence_alike(monkeypatch):
    op_events = [
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 1.0, "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 2.0, "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda **k: op_events)
    r = lab_progress.compute("xss", 0.0, mode="tutorial")
    assert r["success"] is False
    assert r["reading_only"] is True


# ── B. session_manager.execute() refuses guided-mode scripted execution ────
def _fake_record(mode: str):
    return types.SimpleNamespace(
        mode=mode,
        attack=types.SimpleNamespace(state="idle"),
        module=types.SimpleNamespace(steps=[]),
        completed_steps=[],
    )


def test_execute_blocks_guided_mode_even_with_auto_attacks_enabled(monkeypatch):
    import asyncio
    monkeypatch.setattr(session_manager, "auto_attacks_enabled", lambda: True)
    record = _fake_record("tutorial")
    with pytest.raises(RuntimeError, match="reading-only"):
        asyncio.run(session_manager.SessionManager.execute(None, record, loop=None))


def test_execute_still_blocked_for_operator_when_auto_attacks_disabled(monkeypatch):
    import asyncio
    monkeypatch.setattr(session_manager, "auto_attacks_enabled", lambda: False)
    record = _fake_record("lab")
    with pytest.raises(RuntimeError, match="disabled in student mode"):
        asyncio.run(session_manager.SessionManager.execute(None, record, loop=None))


# ── C. report_agent.generate() refuses to synthesize a guided-mode report ──
class _FakeModule:
    module_id = "xss"
    name = "Reflected XSS"


class _FakeSession:
    session_id = "s-guided-1"
    module = _FakeModule()


def test_report_agent_refuses_guided_mode_report():
    report = report_agent.generate(_FakeSession(), events=[], timeline=[], progress={}, mode="tutorial")
    assert report["reading_only"] is True
    assert report["success"] is False
    assert "Operator Mode" in report["message"]
