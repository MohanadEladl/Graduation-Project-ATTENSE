"""
Target-agent evidence + channel-detection tests.

Covers:
  C. detect_via() classification (User-Agent + X-Forwarded-Prefix).
  D. brute_force_pattern synthesized event inherits path/method/via/backend
     from the triggering login_failed event (no hardcoded /auth/login).

These import the vulnerable target app (apps/target-lab/app), which is the
container build source. evidence.py is stdlib-only; main.py needs Flask (present
in the test env) and is exercised via a Flask test request context.
"""
import os
import sys
from pathlib import Path

import pytest

TARGET_APP = Path(__file__).resolve().parents[3] / "apps" / "target-lab" / "app"
sys.path.insert(0, str(TARGET_APP))

import evidence  # noqa: E402
import main as target_main  # noqa: E402


# ── C. detect_via() ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("ua,prefix,expected", [
    ("AttenseZAPRepeater/1.0", "", "zap_repeater"),
    ("AttenseZAPFuzzer/1.0", "", "zap_fuzzer"),
    ("AttenseAttackBox/1.0", "", "attackbox"),
    ("Mozilla/5.0 (LabBrowser)", "/target-zap", "browser"),
    ("Mozilla/5.0 (LabBrowser)", "/target", "browser"),
    ("Mozilla/5.0 (LabBrowser)", "/target-op", "browser"),
    ("curl/8.0.0", "", "unknown"),
])
def test_detect_via_classification(ua, prefix, expected):
    headers = {"User-Agent": ua}
    if prefix:
        headers["X-Forwarded-Prefix"] = prefix
    with target_main.app.test_request_context("/", headers=headers):
        assert target_main.detect_via() == expected


# ── D. brute_force_pattern metadata inheritance ──────────────────────────────
def _fail(ip, path, backend, via, ts_extra=None):
    evidence.record(
        "login_failed", module_id="brute_force", path=path, method="POST",
        source_ip=ip, via=via,
        extra={"backend": backend, "path": path, **(ts_extra or {})},
    )


def test_brute_force_pattern_inherits_operator_metadata():
    evidence.reset()
    ip = "10.20.30.40"
    for _ in range(3):
        _fail(ip, "/op/auth/login", "operator", "zap_fuzzer")
    patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
    assert patterns, "brute_force_pattern should synthesize after 3 failures"
    p = patterns[-1]
    assert p["path"] == "/op/auth/login"          # NOT hardcoded /auth/login
    assert p["method"] == "POST"
    assert p["via"] == "zap_fuzzer"
    assert (p.get("extra") or {}).get("backend") == "operator"


def test_brute_force_pattern_inherits_guided_metadata():
    evidence.reset()
    ip = "10.20.30.41"
    for _ in range(3):
        _fail(ip, "/auth/login", "guided", "browser")
    patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
    assert patterns
    p = patterns[-1]
    assert p["path"] == "/auth/login"
    assert p["via"] == "browser"
    assert (p.get("extra") or {}).get("backend") == "guided"


def test_brute_force_pattern_scoped_per_backend():
    """Operator and guided failures from the same IP must not cross-trigger:
    each (path, backend) needs its own 3 failures."""
    evidence.reset()
    ip = "10.20.30.42"
    _fail(ip, "/op/auth/login", "operator", "zap_fuzzer")
    _fail(ip, "/auth/login", "guided", "browser")
    _fail(ip, "/op/auth/login", "operator", "zap_fuzzer")
    # Only 2 operator + 1 guided failure — below the threshold for either.
    patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
    assert not patterns
