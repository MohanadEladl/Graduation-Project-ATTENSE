"""
Objective-based progress model tests.

Mission COMPLETION is objective-based (reaching the real attack target), while
learning QUALITY (methodology) is scored separately and never blocks completion.

Covers Part 8 of the objective-based-progress change:
  1. A completion event set alone marks the mission successful.
  2. Missing quality events reduce quality_score but do NOT block success.
  3. Browser objective proof completes only for high-confidence objective events.
  4. Guided /auth-style path does not complete Operator Mode.
  5. Correct /op/ objective evidence completes Operator Mode.
  6. The API response exposes success + completion_score + quality_score +
     missing_quality + next_recommended_action.
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

GATED_MODULES = ["recon", "xss", "cmd_injection", "dir_traversal", "file_upload", "csrf"]

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


def _completion_events(module_id, *, path, backend, via):
    """One event per completion group — the minimum objective evidence."""
    return [
        {"event_type": t, "path": path, "method": "GET", "via": via,
         "ts": float(i + 1), "extra": {"backend": backend, "path": path}}
        for i, t in enumerate(lab_progress.completion_event_types(module_id))
    ]


def _patch(monkeypatch, events):
    monkeypatch.setattr(lab_progress, "fetch_events", lambda since=0.0, limit=500: events)


# 1 + 5. Objective evidence alone completes Operator Mode with completion_score 100.
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_completion_events_alone_mark_success(monkeypatch, module_id):
    events = _completion_events(module_id, path=OP_PATH[module_id], backend="operator", via="zap_repeater")
    _patch(monkeypatch, events)
    r = lab_progress.compute(module_id, 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100
    assert r["completed_required"], "completed_required should name the objective evidence"


# 2 + 6. Missing quality lowers quality_score but does not block success, and the
# API surfaces the objective model fields incl. a next recommended action.
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_missing_quality_does_not_block_success(monkeypatch, module_id):
    # Reaches the objective through Repeater only — several methodology signals
    # (marker-first, context-inspected, fuzzer, etc.) are intentionally absent.
    events = _completion_events(module_id, path=OP_PATH[module_id], backend="operator", via="zap_repeater")
    _patch(monkeypatch, events)
    r = lab_progress.compute(module_id, 0.0, mode="lab")
    assert r["success"] is True
    assert r["quality_score"] < 100, "skipping methodology must lower quality, not block completion"
    assert r["missing_quality"], "missing_quality should list the skipped methodology"
    assert r["next_recommended_action"], "a next recommended action should be offered"
    # every missing-quality entry carries an actionable, non-empty recommendation
    assert all(m.get("recommendation") for m in r["missing_quality"])


# 3. Browser-only objective evidence does not complete Operator Mode for modules
#    whose proof must come from a tool. XSS and CSRF are exceptions: browser proof
#    is the objective evidence when it is still on the operator surface.
TOOL_ONLY_MODULES = [m for m in GATED_MODULES if m not in {"xss", "csrf"}]


@pytest.mark.parametrize("module_id", TOOL_ONLY_MODULES)
def test_browser_only_objective_does_not_complete(monkeypatch, module_id):
    events = _completion_events(module_id, path=OP_PATH[module_id], backend="operator", via="browser")
    _patch(monkeypatch, events)
    r = lab_progress.compute(module_id, 0.0, mode="lab")
    assert r["success"] is False
    assert r["completion_score"] == 0
    assert r["warnings"], "a browser-only objective should raise a channel warning"


# CSRF exception: the local browser lure on the /op/ route DOES complete CSRF,
# but only with backend=operator on the approved operator route.
def test_csrf_objective_completes_via_browser_lure(monkeypatch):
    events = _completion_events("csrf", path="/op/profile/update", backend="operator", via="browser")
    _patch(monkeypatch, events)
    r = lab_progress.compute("csrf", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100


def test_xss_browser_operator_objective_proof_completes_with_lower_quality(monkeypatch):
    events = [
        {"event_type": "search_used", "path": "/op/search", "method": "GET",
         "via": "browser", "ts": 1.0, "module_id": "xss",
         "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "browser", "ts": 2.0, "module_id": "xss",
         "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
         "via": "browser", "ts": 3.0, "module_id": "xss",
         "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    _patch(monkeypatch, events)
    r = lab_progress.compute("xss", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100
    assert r["quality_score"] < 100
    reflected = next(c for c in r["evidence"] if c["event_type"] == "reflected_input_detected")
    assert reflected["counts_for_completion"] is True
    assert reflected["counts_for_quality"] is False


# 4. Guided-surface objective evidence does not complete Operator Mode.
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_guided_surface_objective_does_not_complete_operator(monkeypatch, module_id):
    events = _completion_events(module_id, path=GUIDED_PATH[module_id], backend="guided", via="zap_repeater")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


def test_guided_browser_search_does_not_complete_operator_xss(monkeypatch):
    events = _completion_events("xss", path="/search", backend="guided", via="browser")
    _patch(monkeypatch, events)
    assert lab_progress.compute("xss", 0.0, mode="lab")["success"] is False


# via=unknown never completes Operator Mode.
@pytest.mark.parametrize("module_id", GATED_MODULES)
def test_unknown_via_does_not_complete(monkeypatch, module_id):
    events = _completion_events(module_id, path=OP_PATH[module_id], backend="operator", via="unknown")
    _patch(monkeypatch, events)
    assert lab_progress.compute(module_id, 0.0, mode="lab")["success"] is False


def test_wrong_module_id_does_not_complete_xss(monkeypatch):
    events = [
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 1.0, "module_id": "recon",
         "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 2.0, "module_id": "recon",
         "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    _patch(monkeypatch, events)
    assert lab_progress.compute("xss", 0.0, mode="lab")["success"] is False


# XSS worked example from the spec: one payload + reflection via Repeater →
# success, completion 100, quality < 100, marker/context in missing_quality.
def test_xss_worked_example(monkeypatch):
    events = [
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 1.0, "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 2.0, "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    _patch(monkeypatch, events)
    r = lab_progress.compute("xss", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100
    assert r["quality_score"] < 100
    missing_ids = {m["id"] for m in r["missing_quality"]}
    assert "marker_first" in missing_ids
    assert "context_inspected" in missing_ids


# Quality credit accrues from methodology even before the objective is reached.
def test_quality_scored_independently_of_completion(monkeypatch):
    # A benign baseline + capture through Repeater, but no injection proof yet.
    events = [
        {"event_type": "diagnostics_used", "path": "/op/system/ping", "method": "GET",
         "via": "zap_repeater", "ts": 1.0, "extra": {"backend": "operator", "path": "/op/system/ping"}},
    ]
    _patch(monkeypatch, events)
    r = lab_progress.compute("cmd_injection", 0.0, mode="lab")
    assert r["success"] is False
    assert r["completion_score"] == 0
    assert r["quality_score"] > 0, "baseline + repeater usage should earn methodology credit"


# Brute force still requires tool-driven failures, but the final credential
# proof can come from a tool or browser. Repeater confirmation is quality.
def test_brute_force_tool_credential_completes_without_repeater_but_lowers_quality(monkeypatch):
    def ev(t, ts, via="zap_fuzzer"):
        return {"event_type": t, "path": "/op/auth/login", "method": "POST",
                "via": via, "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    events = [*[ev("login_failed", i) for i in range(6)],
              ev("credential_found", 9, via="zap_repeater")]
    _patch(monkeypatch, events)
    r = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100

    # Found during the bulk sweep itself (via=zap_fuzzer) completes the
    # objective after enough failures, but loses Repeater quality.
    events_without_repeater = [*[ev("login_failed", i) for i in range(6)], ev("credential_found", 9)]
    _patch(monkeypatch, events_without_repeater)
    r_without_repeater = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r_without_repeater["success"] is True
    assert r_without_repeater["completion_score"] == 100
    assert r_without_repeater["quality_score"] < 100
    assert any("Repeater" in m["label"] or "Repeater" in m["recommendation"]
               for m in r_without_repeater["missing_quality"])

    # 3 failures alone: not complete, but partial completion score.
    events_few = [ev("login_failed", i) for i in range(3)]
    _patch(monkeypatch, events_few)
    r2 = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r2["success"] is False
    assert 0 < r2["completion_score"] < 100


# A browser login as admin proves the credential was discovered and completes
# after enough tool-driven failures; Repeater remains a quality recommendation.
def test_brute_force_browser_login_completes_after_tool_failures(monkeypatch):
    def ev(t, ts, via):
        return {"event_type": t, "path": "/op/auth/login", "method": "POST",
                "via": via, "ts": ts, "extra": {"backend": "operator", "path": "/op/auth/login"}}
    # Six tool-driven failures + a browser login that emits both success events
    # (auth.py records login_success AND credential_found on a valid login).
    events = [*[ev("login_failed", i, "zap_fuzzer") for i in range(6)],
              ev("login_success", 9, "browser"),
              ev("credential_found", 9, "browser")]
    _patch(monkeypatch, events)
    r = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100
    assert r["quality_score"] < 100
    assert "Repeater" in (r["next_recommended_action"] or ""), "must nudge toward Repeater quality"

    # Re-sending that exact credential through Repeater improves quality.
    events_confirmed = [*events, ev("credential_found", 12, "zap_repeater")]
    _patch(monkeypatch, events_confirmed)
    r2 = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r2["success"] is True
    assert r2["completion_score"] == 100
    assert r2["quality_score"] > r["quality_score"]


def test_brute_force_browser_login_after_tool_pattern_completes_with_lower_quality(monkeypatch):
    def ev(t, ts, via="zap_fuzzer"):
        return {"event_type": t, "path": "/op/auth/login", "method": "POST",
                "via": via, "ts": ts, "module_id": "brute_force",
                "extra": {"backend": "operator", "path": "/op/auth/login"}}

    events = [
        *[ev("login_failed", float(i)) for i in range(6)],
        ev("brute_force_pattern", 7.0),
        ev("login_success", 8.0, via="browser"),
        ev("credential_found", 9.0, via="browser"),
    ]
    _patch(monkeypatch, events)
    r = lab_progress.compute("brute_force", 0.0, mode="lab")
    assert r["success"] is True
    assert r["completion_score"] == 100
    assert r["quality_score"] < 100
    assert any("Repeater" in m["label"] or "Repeater" in m["recommendation"]
               for m in r["missing_quality"])
    credential = next(c for c in r["evidence"] if c["event_type"] == "credential_found")
    assert credential["counts_for_completion"] is True
    assert credential["counts_for_quality"] is False


def test_brute_force_guided_browser_login_does_not_complete_operator(monkeypatch):
    events = [
        {"event_type": "brute_force_pattern", "path": "/auth/login", "method": "POST",
         "via": "browser", "ts": 1.0, "module_id": "brute_force",
         "extra": {"backend": "guided", "path": "/auth/login"}},
        {"event_type": "login_success", "path": "/auth/login", "method": "POST",
         "via": "browser", "ts": 2.0, "module_id": "brute_force",
         "extra": {"backend": "guided", "path": "/auth/login"}},
        {"event_type": "credential_found", "path": "/auth/login", "method": "POST",
         "via": "browser", "ts": 3.0, "module_id": "brute_force",
         "extra": {"backend": "guided", "path": "/auth/login"}},
    ]
    _patch(monkeypatch, events)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False


def test_brute_force_unknown_via_does_not_complete(monkeypatch):
    events = [
        {"event_type": "login_failed", "path": "/op/auth/login", "method": "POST",
         "via": "unknown", "ts": float(i), "module_id": "brute_force",
         "extra": {"backend": "operator", "path": "/op/auth/login"}}
        for i in range(6)
    ]
    events.extend([
        {"event_type": "brute_force_pattern", "path": "/op/auth/login", "method": "POST",
         "via": "unknown", "ts": 7.0, "module_id": "brute_force",
         "extra": {"backend": "operator", "path": "/op/auth/login"}},
        {"event_type": "credential_found", "path": "/op/auth/login", "method": "POST",
         "via": "unknown", "ts": 8.0, "module_id": "brute_force",
         "extra": {"backend": "operator", "path": "/op/auth/login"}},
    ])
    _patch(monkeypatch, events)
    assert lab_progress.compute("brute_force", 0.0, mode="lab")["success"] is False


# ── API shape (Part 8, item D) ───────────────────────────────────────────────
API_FIELDS = [
    "success", "objective", "completion_score", "quality_score",
    "completed_required", "completed_quality", "missing_quality", "warnings",
    "next_recommended_action", "raw_event_count", "counted_event_count",
    "ignored_event_count", "ignored_reasons", "last_observed_events",
    "last_counted_events", "tasks", "objective_tasks",
]


@pytest.mark.parametrize("module_id", GATED_MODULES + ["brute_force"])
def test_compute_returns_full_api_shape(monkeypatch, module_id):
    _patch(monkeypatch, [])  # no events — shape must still be complete
    r = lab_progress.compute(module_id, 0.0, mode="lab")
    for field in API_FIELDS:
        assert field in r, f"{module_id}: compute() response missing {field!r}"
    # ignored_reasons exposes every diagnostic bucket
    for bucket in lab_progress.IGNORED_REASONS:
        assert bucket in r["ignored_reasons"], f"missing ignore bucket {bucket}"
    # typed tasks carry the required id/label/done/type
    assert r["objective_tasks"], "objective_tasks should always include the required objective"
    assert r["objective_tasks"][0]["type"] == "required"
    for t in r["objective_tasks"]:
        for k in ("id", "label", "done", "type"):
            assert k in t


def test_ignored_diagnostics_classify_wrong_channel(monkeypatch):
    # Low-level browser evidence, guided objective evidence, and unknown-channel
    # objective evidence are ignored + explained.
    events = [
        {"event_type": "search_used", "path": "/op/search", "method": "GET",
         "via": "browser", "ts": 1.0, "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/search", "method": "GET",
         "via": "zap_repeater", "ts": 2.0, "extra": {"backend": "guided", "path": "/search"}},
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "unknown", "ts": 3.0, "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    _patch(monkeypatch, events)
    r = lab_progress.compute("xss", 0.0, mode="lab")
    assert r["success"] is False
    assert r["raw_event_count"] == 3
    assert r["counted_event_count"] == 0
    assert r["ignored_event_count"] == 3
    assert r["ignored_reasons"]["ignored_wrong_via"] >= 1     # unknown on /op/
    assert r["ignored_reasons"]["ignored_wrong_backend"] >= 1  # guided-surface event
    assert r["last_observed_events"], "diagnostics should list recently observed events"


# ── Report reflects objective vs skipped methodology (Part 8, item 6) ────────
class _FakeModule:
    module_id = "xss"
    name = "Reflected XSS"
    mitre = {"tactics": [], "techniques": []}


class _FakeSession:
    def __init__(self):
        import threading
        self.session_id = "s-obj-1"
        self.module = _FakeModule()
        self.module_id = "xss"
        self.variant_id = None
        self.mission_started_at = 0.0
        self.logs = []
        self.log_lock = threading.Lock()
        self.mutation_timeline = []
        self.learning_completed_at = None


def test_report_explains_objective_and_missing_methodology(monkeypatch):
    monkeypatch.setenv("REPORT_AI_COACH", "0")  # deterministic rule-based prose, no Ollama
    events = [
        {"event_type": "xss_payload_observed", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 1.0, "extra": {"backend": "operator", "path": "/op/search"}},
        {"event_type": "reflected_input_detected", "path": "/op/search", "method": "GET",
         "via": "zap_repeater", "ts": 2.0, "extra": {"backend": "operator", "path": "/op/search"}},
    ]
    _patch(monkeypatch, events)
    progress = lab_progress.compute("xss", 0.0, mode="lab")

    report = report_agent.generate(_FakeSession(), events=events, timeline=[], progress=progress, mode="lab")

    assert report["success"] is True
    assert report["completion_score"] == 100
    assert report["quality_score"] < 100
    # Objective reached appears in did-right; skipped methodology appears in missed.
    assert any("objective reached" in d["title"].lower() for d in report["what_you_did_right"])
    assert report["missing_quality"], "report should carry the skipped methodology"
    assert any(m.get("how_to_fix") for m in report["what_you_missed"]), \
        "missed methodology entries should include an actionable recommendation"
