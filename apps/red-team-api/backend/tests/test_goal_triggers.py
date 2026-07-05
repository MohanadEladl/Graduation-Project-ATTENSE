"""
Goal-trigger engine tests (the new Red Team completion model).

A mission is COMPLETE the instant its goal event is observed on the operator
target — from ANY local channel (browser, AttackBox, ZAP Repeater/Fuzzer, curl,
manual entry, or an uncaptured via="unknown"). Tool choice only shapes the
quality score/report, never completion. Lab-boundary safety is preserved:
guided-surface, wrong-module, and random events never complete.
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

from backend import lab_progress, report_agent  # noqa: E402


def _ev(event_type, path, via, ts=1.0, module_id=None, backend="operator"):
    e = {"event_type": event_type, "path": path, "method": "POST", "via": via,
         "ts": ts, "extra": {"backend": backend, "path": path}}
    if module_id:
        e["module_id"] = module_id
    return e


def _patch(monkeypatch, events):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)


def _run(module_id, events, monkeypatch):
    _patch(monkeypatch, events)
    return lab_progress.compute(module_id, 0.0, mode="lab")


# 1. Brute Force browser-only success completes.
def test_brute_force_browser_only_completes(monkeypatch):
    events = [
        _ev("login_success", "/op/auth/login", "browser", ts=1.0),
        _ev("credential_found", "/op/auth/login", "browser", ts=1.0),
    ]
    r = _run("brute_force", events, monkeypatch)
    assert r["goal_triggered"] is True
    assert r["success"] is True
    assert r["status"] == "complete"
    assert r["quality_score"] < 100
    assert "repeatable tooling" in r["quality_feedback"].lower() \
        or "did not" in r["quality_feedback"].lower()


# 2. Brute Force with NO failed attempts still completes.
def test_brute_force_no_failed_attempts_completes(monkeypatch):
    events = [_ev("credential_found", "/op/auth/login", "browser", ts=1.0)]
    r = _run("brute_force", events, monkeypatch)
    assert r["success"] is True
    assert r["trigger_event"] == "credential_found"


# 3. XSS: one browser payload proof completes.
def test_xss_one_browser_payload_completes(monkeypatch):
    events = [_ev("reflected_input_detected", "/op/search", "browser", ts=1.0)]
    r = _run("xss", events, monkeypatch)
    assert r["success"] is True
    assert r["quality_score"] < 100


def test_xss_payload_observed_alone_completes(monkeypatch):
    events = [_ev("xss_payload_observed", "/op/search", "browser", ts=1.0)]
    assert _run("xss", events, monkeypatch)["success"] is True


# 4. Command Injection: direct goal completes (browser or unknown, no ZAP).
@pytest.mark.parametrize("via", ["browser", "unknown"])
def test_cmd_injection_direct_goal_completes(monkeypatch, via):
    events = [_ev("command_injection_detected", "/op/system/ping", via, ts=1.0)]
    r = _run("cmd_injection", events, monkeypatch)
    assert r["success"] is True
    assert r["quality_score"] < 100


# 5. Directory Traversal: direct goal completes on any local via.
@pytest.mark.parametrize("via", ["browser", "attackbox", "unknown"])
def test_dir_traversal_direct_goal_completes(monkeypatch, via):
    events = [_ev("sensitive_file_disclosed", "/op/files/read", via, ts=1.0)]
    assert _run("dir_traversal", events, monkeypatch)["success"] is True


# 6. File Upload: direct goal completes on any local via.
@pytest.mark.parametrize("goal", ["dangerous_extension_accepted", "unrestricted_upload_detected"])
def test_file_upload_direct_goal_completes(monkeypatch, goal):
    events = [_ev(goal, "/op/files/upload", "browser", ts=1.0)]
    assert _run("file_upload", events, monkeypatch)["success"] is True


# 7. CSRF: browser goal completes.
def test_csrf_browser_goal_completes(monkeypatch):
    events = [_ev("profile_changed_without_csrf", "/op/profile/update", "browser", ts=1.0)]
    assert _run("csrf", events, monkeypatch)["success"] is True


# 8. Negative safety tests.
def test_wrong_module_id_does_not_complete(monkeypatch):
    # xss goal event tagged as recon must not complete xss.
    events = [_ev("reflected_input_detected", "/op/search", "zap_repeater", ts=1.0, module_id="recon")]
    assert _run("xss", events, monkeypatch)["success"] is False


def test_guided_legacy_path_does_not_complete_operator(monkeypatch):
    events = [_ev("reflected_input_detected", "/search", "browser", ts=1.0, backend="guided")]
    assert _run("xss", events, monkeypatch)["success"] is False


def test_random_unrelated_event_does_not_complete(monkeypatch):
    events = [_ev("portal_visited", "/op/", "browser", ts=1.0)]
    assert _run("xss", events, monkeypatch)["success"] is False


def test_tutorial_mode_never_triggers_goal(monkeypatch):
    events = [_ev("reflected_input_detected", "/op/search", "zap_repeater", ts=1.0)]
    _patch(monkeypatch, events)
    r = lab_progress.compute("xss", 0.0, mode="tutorial")
    assert r["goal_triggered"] is False
    assert r["reading_only"] is True


# 9. Report tests: browser-only completed XSS.
def test_report_for_browser_only_xss_says_reached_and_recommends_tools(monkeypatch):
    events = [_ev("reflected_input_detected", "/op/search", "browser", ts=1.0)]
    progress = _run("xss", events, monkeypatch)
    assert progress["success"] is True

    grade, score = report_agent._grade(progress, (1, 0))  # more browser than tools
    assert grade != "F", "a completed mission must not be graded a failure"
    assert score < 90, "browser-only methodology should score low/medium, not top"

    coaching = report_agent._rule_based_coaching(progress, {"name": "Reflected XSS"})
    assert "reached the objective" in coaching.lower()
    assert "zap" in coaching.lower() or "attackbox" in coaching.lower()
    assert "not completed" not in coaching.lower()
    assert "was not" not in coaching.lower()


def test_report_tool_run_scores_higher_than_browser(monkeypatch):
    browser = _run("xss", [_ev("reflected_input_detected", "/op/search", "browser", ts=1.0)], monkeypatch)
    tool = _run("xss", [_ev("reflected_input_detected", "/op/search", "zap_repeater", ts=1.0)], monkeypatch)
    _, s_browser = report_agent._grade(browser, (1, 0))
    _, s_tool = report_agent._grade(tool, (0, 1))
    assert s_tool >= s_browser
