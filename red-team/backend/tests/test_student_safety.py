import os
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
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is True
