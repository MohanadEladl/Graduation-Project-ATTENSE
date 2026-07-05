import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest


SERVICE_ROOT = Path(__file__).resolve().parents[2]
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(SERVICE_ROOT))


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


LAB_MODULES = (
    "recon",
    "xss",
    "cmd_injection",
    "dir_traversal",
    "file_upload",
    "csrf",
    "brute_force",
)

def _load_mission_briefing_data():
    script = """
import { LAB_REQUIRED_TOOLS, MISSION_BRIEFINGS } from './frontends/red-team/src/data/missionBriefings.js';

const modules = ['recon', 'xss', 'cmd_injection', 'dir_traversal', 'file_upload', 'csrf', 'brute_force'];
const data = { briefings: {}, tools: {}, commandFields: [] };

function walkCommandFields(value, path = []) {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((item, idx) => walkCommandFields(item, [...path, String(idx)]));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase();
    if ((lower === 'command' || lower === 'commands' || lower.endsWith('command') || lower.endsWith('commands'))) {
      if (typeof child === 'string') {
        data.commandFields.push({ path: [...path, key].join('.'), command: child });
      } else if (Array.isArray(child)) {
        for (const command of child) {
          if (typeof command === 'string') data.commandFields.push({ path: [...path, key].join('.'), command });
        }
      }
    }
    walkCommandFields(child, [...path, key]);
  }
}

for (const moduleId of modules) {
  const briefing = MISSION_BRIEFINGS[moduleId] || {};
  data.tools[moduleId] = LAB_REQUIRED_TOOLS[moduleId] || [];
  data.briefings[moduleId] = {
    operatorHints: briefing.operatorHints || [],
    tutorialStepsCount: Array.isArray(briefing.tutorial_steps) ? briefing.tutorial_steps.length : 0,
    successCondition: briefing.successCondition || '',
  };
  walkCommandFields(briefing, [moduleId]);
}

process.stdout.write(JSON.stringify(data));
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


def test_mission_briefings_do_not_export_rigid_lab_checklists():
    """The frontend briefing data should not reintroduce rigid lab checklist exports."""
    source = (ROOT / "frontends" / "red-team" / "src" / "data" / "missionBriefings.js").read_text(
        encoding="utf-8"
    )
    assert "LAB_STEPS_BY_MODULE" not in source
    assert "REQUIRED_TOOLS_BY_MODULE" not in source
    assert "labStepsFor" not in source


def test_legacy_red_team_routes_and_duplicate_constants_stay_removed():
    frontend = ROOT / "frontends" / "red-team" / "src"
    backend_main = (SERVICE_ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    app = (frontend / "App.jsx").read_text(encoding="utf-8")
    client = (frontend / "api" / "client.js").read_text(encoding="utf-8")
    reports = (frontend / "routes" / "Reports.jsx").read_text(encoding="utf-8")
    gauntlet = (frontend / "routes" / "Gauntlet.jsx").read_text(encoding="utf-8")
    workspace = (frontend / "routes" / "Workspace.jsx").read_text(encoding="utf-8")

    assert not (frontend / "routes" / "AttackReport.jsx").exists()
    assert not (SERVICE_ROOT / "backend" / "lab_analysis.py").exists()

    for legacy in ("AttackReport", "attack-report", "getAttackReport"):
        assert legacy not in app
        assert legacy not in client
        assert legacy not in backend_main

    for legacy in ("labAnalysis", "lab-analysis", "LabAnalysisSection"):
        assert legacy not in client
        assert legacy not in reports
        assert legacy not in backend_main

    assert "CHAIN_META" not in gauntlet
    assert "CHAIN_ORDER" not in gauntlet
    assert "MUTATION_DEFS" not in gauntlet
    assert "DEFENSE_DETAILS" not in workspace


def test_briefing_command_fields_match_attackbox_validator():
    """Any explicit command field that reappears in briefings must execute safely."""
    data = _load_mission_briefing_data()
    failures = []
    for item in data["commandFields"]:
        err = operator_api.validate_command(item["command"])
        if err:
            failures.append(f"{item['path']}: {item['command']!r} -> {err}")

    assert not failures, "\n".join(failures)


def test_operator_payload_guidance_uses_zap_not_attackbox_commands():
    """Payload-heavy modules should steer HTTP payload work to ZAP, not shell commands."""
    data = _load_mission_briefing_data()

    for module_id in ("xss", "cmd_injection", "dir_traversal", "file_upload", "csrf"):
        joined = "\n".join(data["briefings"][module_id]["operatorHints"]).lower()
        assert "repeater" in joined or "fuzzer" in joined, f"{module_id} should point payload work to ZAP"
        assert "attackbox command" not in joined, f"{module_id} should not be terminal-command-first"


def test_each_module_has_operator_guidance_and_success_criteria():
    data = _load_mission_briefing_data()

    for module_id in LAB_MODULES:
        briefing = data["briefings"][module_id]

        assert data["tools"][module_id], f"{module_id} needs lab tool labels"
        assert briefing["tutorialStepsCount"] > 0, f"{module_id} needs guided tutorial steps"
        assert len(briefing["operatorHints"]) >= 4, f"{module_id} needs staged operator hints"
        assert briefing["successCondition"], f"{module_id} needs success criteria"


def test_operator_hints_do_not_reveal_direct_solutions():
    data = _load_mission_briefing_data()
    forbidden = (
        "password123",
        "br3akme",
        "admin:password",
        "tr0ub4dor",
        "s3rvice@cct",
        "guest:guest",
        "root:x:0:0",
        "../../etc/passwd",
        "<script>alert",
        "127.0.0.1$(",
    )

    for module_id, briefing in data["briefings"].items():
        joined = "\n".join(briefing["operatorHints"]).lower()
        for secret in forbidden:
            assert secret.lower() not in joined, f"{module_id} operator hint leaks {secret!r}"


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


def test_operator_brute_force_completes_from_credential_any_via(monkeypatch):
    """Goal-trigger model: a real credential on the operator login completes the
    mission from ANY local channel, with NO failed-attempt requirement. Only the
    guided surface (backend != operator) is still refused."""
    def ev(event_type, path, backend, via="zap_fuzzer", ts=1.0):
        return {
            "event_type": event_type,
            "path": path,
            "method": "POST",
            "via": via,
            "ts": ts,
            "extra": {"backend": backend, "path": path},
        }

    # Guided surface never completes an operator mission (lab-boundary safety).
    guided = [ev("credential_found", "/auth/login", "guided", ts=9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: guided)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False

    # Operator credential completes via every local channel — zero failed
    # attempts required, even an uncaptured/empty/missing via.
    for via in ("zap_repeater", "zap_fuzzer", "attackbox", "browser", "unknown", ""):
        events = [ev("credential_found", "/op/auth/login", "operator", via=via, ts=9)]
        monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
        r = lab_progress.compute("brute_force", 0.0, mode="lab")
        assert r["success"] is True, f"via={via!r} credential should complete"
        assert r["goal_triggered"] is True

    missing_via = [ev("credential_found", "/op/auth/login", "operator", ts=9)]
    for event in missing_via:
        event.pop("via", None)
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: missing_via)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is True

    # login_success alone also completes.
    ls = [ev("login_success", "/op/auth/login", "operator", via="browser", ts=9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: ls)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is True

    # Tool credential scores at least as high a quality as a browser credential.
    tool = [ev("credential_found", "/op/auth/login", "operator", via="zap_repeater", ts=9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: tool)
    q_tool = lab_progress.compute("brute_force", 0.0, mode="lab")["quality_score"]
    browser = [ev("credential_found", "/op/auth/login", "operator", via="browser", ts=9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: browser)
    q_browser = lab_progress.compute("brute_force", 0.0, mode="lab")["quality_score"]
    assert q_browser <= q_tool


@pytest.mark.parametrize("via", ["attackbox", "zap_repeater", "zap_fuzzer"])
def test_operator_completes_via_each_approved_tool_for_discovery(monkeypatch, via):
    """Discovery (the 6+ failed attempts) can come from any approved local
    tool channel; Repeater confirmation remains the highest-quality finish."""
    def ev(event_type, ts, confirm_via=None):
        return {"event_type": event_type, "path": "/op/auth/login", "method": "POST",
                "via": confirm_via or via, "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)],
              ev("credential_found", 9, confirm_via="zap_repeater")]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    progress = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert progress["success"] is True
    assert progress["brute_force_activity"]["failed_attempt_count"] == 6
    assert via in progress["brute_force_activity"]["tools_observed"]


@pytest.mark.parametrize("via", ["attackbox", "zap_fuzzer"])
def test_bulk_tool_credential_completes_but_misses_repeater_quality(monkeypatch, via):
    """A credential found mid-sweep by a bulk tool (Fuzzer/Hydra via AttackBox)
    completes after enough failed attempts, but does not earn Repeater quality."""
    def ev(event_type, ts, this_via=via):
        return {"event_type": event_type, "path": "/op/auth/login", "method": "POST",
                "via": this_via, "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)], ev("credential_found", 9)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    progress = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert progress["success"] is True
    assert progress["completion_score"] == 100
    assert progress["quality_score"] < 100
    assert progress["brute_force_activity"]["credential_found"] is True
    assert progress["brute_force_activity"]["credential_confirmed_via_repeater"] is False
    assert any("Repeater" in m["label"] or "Repeater" in m["recommendation"]
               for m in progress["missing_quality"])


def test_operator_login_success_also_completes(monkeypatch):
    """credential_found OR login_success should satisfy the credential requirement."""
    def ev(event_type, ts):
        return {"event_type": event_type, "path": "/op/auth/login", "method": "POST",
                "via": "zap_repeater", "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)], ev("login_success", 9),
              ev("credential_found", 10)]
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is True
