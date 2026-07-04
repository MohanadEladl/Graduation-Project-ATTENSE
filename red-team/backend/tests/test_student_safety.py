import json
import os
import subprocess
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
        DockerException=docker_error,
        NotFound=docker_error,
        APIError=docker_error,
    )
    sys.modules["docker"] = docker_stub


from backend import lab_progress, operator_api, session_manager  # noqa: E402


def _load_mission_briefing_commands():
    script = """
import { LAB_STEPS_BY_MODULE } from './red-team/frontend/src/data/missionBriefings.js';

const modules = ['recon', 'xss', 'cmd_injection', 'dir_traversal', 'file_upload', 'csrf', 'brute_force'];
const commands = [];

for (const moduleId of modules) {
  const steps = LAB_STEPS_BY_MODULE[moduleId] || [];
  for (const step of steps) {
    if (typeof step.command === 'string') {
      commands.push({ moduleId, step: step.n, command: step.command });
    }
    if (Array.isArray(step.commands)) {
      for (const command of step.commands) {
        commands.push({ moduleId, step: step.n, command });
      }
    }
  }
}

process.stdout.write(JSON.stringify(commands));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_auto_attacks_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_AUTO_ATTACKS", raising=False)
    assert session_manager.auto_attacks_enabled() is False

    monkeypatch.setenv("ENABLE_AUTO_ATTACKS", "true")
    assert session_manager.auto_attacks_enabled() is True

    monkeypatch.setenv("ENABLE_AUTO_ATTACKS", "false")
    assert session_manager.auto_attacks_enabled() is False


def test_attackbox_validate_allowed_and_blocked_examples():
    allowed = [
        "nmap target-agent",
        "curl -I http://target-agent",
        "curl -X POST http://target-agent/op/auth/login -d username=student&password=wrong",
        "ffuf -w /wordlists/routes.txt -u http://target-agent/FUZZ",
        (
            "hydra -L /wordlists/users.txt -P /wordlists/passwords-small.txt "
            'target-agent http-post-form "/op/auth/login:username=^USER^&password=^PASS^:Invalid credentials"'
        ),
    ]
    blocked = [
        "nmap google.com",
        "nmap 8.8.8.8",
        "curl http://example.com",
        "ping google.com",
        "dig google.com",
        "nslookup google.com",
        "nc google.com 80",
        'python3 -c "import requests; requests.get(\'http://example.com\')"',
        'bash -lc "curl http://example.com"',
    ]

    assert [operator_api.validate_command(cmd) for cmd in allowed] == [None] * len(allowed)
    assert all(operator_api.validate_command(cmd) == operator_api.BLOCKED_EXTERNAL_MSG for cmd in blocked)


def test_lab_briefing_attackbox_commands_match_validator():
    """Every command rendered as an AttackBox copy block must execute safely."""
    commands = _load_mission_briefing_commands()
    assert commands

    failures = []
    for item in commands:
        err = operator_api.validate_command(item["command"])
        if err:
            failures.append(
                f"{item['moduleId']} step {item['step']}: {item['command']!r} -> {err}"
            )

    assert not failures, "\n".join(failures)


def test_zap_target_normalization_blocks_external_urls():
    assert operator_api.normalize_zap_target_path("/auth/login") == "/auth/login"
    assert operator_api.normalize_zap_target_path("/op/auth/login") == "/op/auth/login"
    assert operator_api.normalize_zap_target_path("http://target-agent/auth/login") == "/auth/login"
    assert operator_api.normalize_zap_target_path("https://target-agent/op/auth/login") == "/op/auth/login"

    for target in [
        "http://example.com",
        "https://google.com",
        "http://8.8.8.8",
        "http://target-agent/http://target-agent/auth/login",
    ]:
        with pytest.raises(ValueError, match="external targets are not allowed"):
            operator_api.normalize_zap_target_path(target)


def test_zap_browse_path_mapping_is_local_only():
    # Operator surfaces map under /op/; app-level assets/telemetry stay bare.
    assert operator_api._zap_browse_target_path("auth/login") == "/op/auth/login"
    assert operator_api._zap_browse_target_path("") == "/op/"
    assert operator_api._zap_browse_target_path("profile/") == "/op/profile/"
    assert operator_api._zap_browse_target_path("lab/__attense_trace.js") == "/lab/__attense_trace.js"
    assert operator_api._zap_browse_target_path("static/x.css") == "/static/x.css"
    # Any smuggled scheme is refused (nginx collapses http:// to http:/).
    for evil in ("http://example.com/x", "https://8.8.8.8", "http:/example.com/x"):
        assert operator_api._zap_browse_target_path(evil) is None
    # A bare //host has no scheme; it degrades to a harmless LOCAL path on
    # target-agent (a 404), never an external request — the upstream host in
    # browse_through_zap is always hard-coded to target-agent.
    mapped = operator_api._zap_browse_target_path("//evil.com")
    assert mapped is None or mapped.startswith("/op/")


def test_zap_browse_rejects_external_without_touching_network(monkeypatch):
    # If mapping refuses the path, requests must never be called at all.
    called = {"n": 0}
    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("requests.request must not run for a blocked path")
    monkeypatch.setattr(operator_api.requests, "request", _boom)
    out = operator_api.browse_through_zap("GET", "http://example.com/x")
    assert out["status_code"] == 400
    assert called["n"] == 0


def test_zap_history_model_full_fields_and_truncation():
    big = "A" * (operator_api.MAX_HISTORY_BODY_LEN + 5000)
    row = operator_api._record_zap_history(
        "POST", "/op/auth/login", full_url="http://target-agent/op/auth/login",
        status_code="401", request_headers={"Content-Type": "x"},
        request_body="u=a&p=b", response_headers="HTTP/1.1 401\nX: y",
        response_body=big, response_length=len(big), source="zap_repeater",
        session_id="s1", module_id="brute_force",
    )
    for key in ("id", "method", "full_url", "path", "request_headers", "request_body",
                "response_status", "response_headers", "response_body",
                "response_length", "source", "session_id", "module_id", "timestamp"):
        assert key in row, f"history row missing {key}"
    # Oversized bodies are truncated so they can't break the Inspector UI.
    assert len(row["response_body"]) <= operator_api.MAX_HISTORY_BODY_LEN + 64
    assert "truncated" in row["response_body"]
    assert row["source"] == "zap_repeater"
    assert row["session_id"] == "s1" and row["module_id"] == "brute_force"
    assert row["response_status"] == "401"


def test_operator_brute_force_requires_op_path_and_six_failures(monkeypatch):
    def ev(event_type, path, backend, via="zap_fuzzer", ts=1.0):
        return {
            "event_type": event_type,
            "path": path,
            "method": "POST",
            "via": via,
            "ts": ts,
            "extra": {"backend": backend, "path": path},
        }

    wrong_path = [
        *[ev("login_failed", "/auth/login", "guided", ts=i) for i in range(6)],
        ev("credential_found", "/auth/login", "guided", ts=9),
    ]
    too_few = [
        *[ev("login_failed", "/op/auth/login", "operator", ts=i) for i in range(3)],
        ev("credential_found", "/op/auth/login", "operator", ts=9),
    ]
    complete = [
        *[ev("login_failed", "/op/auth/login", "operator", ts=i) for i in range(6)],
        ev("credential_found", "/op/auth/login", "operator", ts=9),
    ]
    browser_complete = [
        *[ev("login_failed", "/op/auth/login", "operator", via="browser", ts=i) for i in range(6)],
        ev("credential_found", "/op/auth/login", "operator", via="browser", ts=9),
    ]
    legacy_zap_complete = [
        *[ev("login_failed", "/op/auth/login", "operator", via="unknown", ts=i) for i in range(6)],
        ev("credential_found", "/op/auth/login", "operator", via="unknown", ts=9),
    ]
    empty_via_complete = [
        *[ev("login_failed", "/op/auth/login", "operator", via="", ts=i) for i in range(6)],
        ev("credential_found", "/op/auth/login", "operator", via="", ts=9),
    ]
    missing_via_complete = [
        *[ev("login_failed", "/op/auth/login", "operator", ts=i) for i in range(6)],
        ev("credential_found", "/op/auth/login", "operator", ts=9),
    ]
    for event in missing_via_complete:
        event.pop("via", None)

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: wrong_path)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: too_few)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: browser_complete)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: complete)
    progress = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert progress["success"] is True
    assert progress["brute_force_activity"]["failed_attempt_count"] == 6
    assert progress["brute_force_activity"]["path"] == "/op/auth/login"

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: legacy_zap_complete)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: empty_via_complete)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: missing_via_complete)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False


@pytest.mark.parametrize("via", ["attackbox", "zap_repeater", "zap_fuzzer"])
def test_operator_completes_via_each_approved_tool(monkeypatch, via):
    """Each approved local tool channel can complete Operator Mode on
    /op/auth/login with 6+ failures + a found credential."""
    def ev(event_type, ts):
        return {"event_type": event_type, "path": "/op/auth/login", "method": "POST",
                "via": via, "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)], ev("credential_found", 9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    progress = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert progress["success"] is True
    assert progress["brute_force_activity"]["failed_attempt_count"] == 6
    assert via in progress["brute_force_activity"]["tools_observed"]


def test_operator_login_success_also_completes(monkeypatch):
    """credential_found OR login_success should satisfy the credential requirement."""
    def ev(event_type, ts):
        return {"event_type": event_type, "path": "/op/auth/login", "method": "POST",
                "via": "zap_repeater", "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)], ev("login_success", 9),
              ev("credential_found", 10)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is True
