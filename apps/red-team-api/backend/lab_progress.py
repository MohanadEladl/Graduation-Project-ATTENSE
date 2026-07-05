"""
backend/lab_progress.py — Computes mission progress from target-agent events.

Pulls events from `target-agent:/lab/events?since=...` and matches them
against per-module success criteria. Also includes tool command evidence
from lab mode (AttackBox). Returns a structured response the
LearningPanel renders directly.

Modes (product contract — see docs/redteam-guided-mode-reading-only.md):
  tutorial (aka "guided") — READING-ONLY. No attack execution, no
    evidence-based completion, no target-agent scoring. compute() returns a
    static reading_only=True payload immediately — see
    `_guided_reading_only_response()` — without fetching any events.
  lab (aka "operator")    — the only mode that runs the real lab pipeline:
    /op/ route + approved local-tool evidence, objective-based completion,
    quality scoring, ignored-evidence diagnostics.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import urllib.request
import urllib.error
import json

# Where to reach the target-agent's evidence API. In docker-compose,
# resolved by service hostname.
TARGET_AGENT_URL = os.getenv("LAB_EVENTS_URL", "http://target-agent")
OPERATOR_TOOL_VIA = {"attackbox", "zap_repeater", "zap_fuzzer"}
BRUTE_FORCE_MIN_FAILURES = 6


def fetch_events(since: float = 0.0,
                 module_id: Optional[str] = None,
                 limit: int = 500) -> List[Dict[str, Any]]:
    """Fetch raw events from target-agent. Returns [] on any error."""
    qs = f"since={since}&limit={limit}"
    if module_id:
        qs += f"&module_id={module_id}"
    url = f"{TARGET_AGENT_URL}/lab/events?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("events", [])
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
        return []


def _event_extra(e: Dict[str, Any]) -> Dict[str, Any]:
    extra = e.get("extra")
    return extra if isinstance(extra, dict) else {}


def _event_path(e: Dict[str, Any]) -> str:
    return str(e.get("path") or _event_extra(e).get("path") or "")


def _event_backend(e: Dict[str, Any]) -> str:
    extra_backend = _event_extra(e).get("backend")
    if extra_backend:
        return str(extra_backend)
    path = _event_path(e)
    if path.startswith("/op/"):
        return "operator"
    if path.startswith("/auth/"):
        return "guided"
    return ""


def _is_operator_tool_event(e: Dict[str, Any]) -> bool:
    return str(e.get("via") or "") in OPERATOR_TOOL_VIA


# Derived/synthetic events are minted by the target-agent's pattern detector
# rather than by a concrete /op/ route, so they inherit their via + backend from
# the triggering request and have no /op/ path of their own. They are gated on
# backend + tool channel, but exempt from the /op/ path-prefix requirement.
DERIVED_EVENT_TYPES = {"brute_force_pattern", "recon_sequence_observed"}


# Some objectives are naturally proven in the browser, but only when the event
# itself is high-confidence proof of the objective. Low-level methodology events
# such as search_used or login_failed still require tool-quality evidence.
BROWSER_COMPLETION_EVENT_TYPES = {
    "csrf": {"profile_changed_without_csrf"},
    "xss": {"xss_payload_observed", "reflected_input_detected", "stored_payload_observed"},
}
BROWSER_COMPLETABLE_MODULES = set(BROWSER_COMPLETION_EVENT_TYPES)


# ── Goal-trigger engine ──────────────────────────────────────────────────────
# A mission is COMPLETE the instant its goal event is observed on the active lab
# target — no task ladder, no required failure count, no tool requirement. It
# does NOT matter whether the student used the Browser, AttackBox, ZAP
# Repeater/Fuzzer, curl, or manual form entry; tool choice only shapes the
# quality score/report, never completion. Lab-boundary safety is still enforced:
# the goal event must have operator scope (backend=operator + /op/* path, or a
# derived operator event) and match the module. Guided-surface and external
# evidence never trigger a goal. via is deliberately ignored for completion —
# even via="unknown" completes (it just tanks the quality score).
GOAL_TRIGGERS: Dict[str, set] = {
    "recon":         {"recon_sequence_observed", "hidden_clue_accessed"},
    "brute_force":   {"credential_found", "login_success"},
    "xss":           {"reflected_input_detected", "xss_payload_observed", "stored_payload_observed"},
    "cmd_injection": {"command_injection_detected"},
    "dir_traversal": {"sensitive_file_disclosed", "lab_file_disclosed"},
    "file_upload":   {"dangerous_extension_accepted", "unrestricted_upload_detected",
                      "uploaded_file_retrieved"},
    "csrf":          {"profile_changed_without_csrf"},
}

# recon may also complete on enough route-discovery evidence (mapping proof),
# even if the derived recon_sequence_observed event never fired.
RECON_ROUTE_DISCOVERY_MIN = 3


def _event_triggers_goal(e: Dict[str, Any], module_id: str, *, is_lab: bool) -> bool:
    """True when a single event is a goal trigger for the module: a GOAL event
    type observed with valid operator lab scope. via-INDEPENDENT by design."""
    return (
        e.get("event_type") in GOAL_TRIGGERS.get(module_id or "", set())
        and _event_has_operator_scope(e, is_lab=is_lab, module_id=module_id)
    )


def _goal_trigger(module_id: str, events: List[Dict[str, Any]], *, is_lab: bool):
    """Resolve the mission goal from observed events.

    Returns (triggered: bool, trigger_event: str|None, trigger_reason: str|None).
    Completion fires on the FIRST goal event seen, from any local channel.
    """
    hits = [e for e in events if _event_triggers_goal(e, module_id, is_lab=is_lab)]
    if hits:
        first = min(hits, key=lambda e: e.get("ts") or 0)
        et = first.get("event_type")
        return True, et, f"Goal reached: '{_evidence_title(et)}' observed on the operator target."
    # recon fallback — enough operator route-discovery proves the map was built.
    if module_id == "recon":
        routes = [
            e for e in events
            if e.get("event_type") == "route_discovered"
            and _event_has_operator_scope(e, is_lab=is_lab, module_id=module_id)
        ]
        if len(routes) >= RECON_ROUTE_DISCOVERY_MIN:
            return True, "route_discovered", (
                f"Goal reached: mapped {len(routes)} operator routes."
            )
    return False, None, None


def _allowed_via_for(module_id: Optional[str]) -> set:
    """Approved operator `via` channels for objective completion."""
    if module_id in BROWSER_COMPLETABLE_MODULES:
        return OPERATOR_TOOL_VIA | {"browser"}
    return set(OPERATOR_TOOL_VIA)


def _event_module_matches(e: Dict[str, Any], module_id: Optional[str]) -> bool:
    """Explicitly wrong module tags must not complete another module.

    Older tests and a few synthetic/tool events omit module_id, so absence is
    treated as unscoped legacy evidence. A present module_id is authoritative.
    """
    if not module_id:
        return True
    event_module = e.get("module_id")
    return not event_module or event_module == module_id


def _event_has_operator_scope(e: Dict[str, Any], *, is_lab: bool,
                              module_id: Optional[str]) -> bool:
    if not is_lab:
        return False
    if not _event_module_matches(e, module_id):
        return False
    backend = _event_backend(e)
    if backend != "operator":
        return False
    if e.get("event_type") in DERIVED_EVENT_TYPES:
        return True
    return _event_path(e).startswith("/op/")


def _event_counts_for_completion(e: Dict[str, Any], *, is_lab: bool,
                                 module_id: Optional[str] = None) -> bool:
    """Gate objective completion evidence — the goal-trigger rule.

    An event counts toward completion when it is a GOAL event (see
    GOAL_TRIGGERS) observed with valid operator lab scope (Operator Mode,
    backend=operator, /op/* path or a derived operator event, matching module).
    Completion is deliberately via-INDEPENDENT: Browser, AttackBox, ZAP
    Repeater/Fuzzer, curl, and even an uncaptured via="unknown" all count —
    tool choice affects only the quality score, never completion. Guided-surface
    and external evidence still never count.
    """
    return _event_triggers_goal(e, module_id or "", is_lab=is_lab)


def _event_counts_for_quality(e: Dict[str, Any], *, is_lab: bool,
                              module_id: Optional[str] = None) -> bool:
    """Gate methodology/quality evidence.

    Quality remains stricter than completion: only local AttackBox/ZAP tool
    channels count as high-quality evidence. Browser completion can finish a
    mission, but it will not satisfy methodology tasks.
    """
    return (
        _event_has_operator_scope(e, is_lab=is_lab, module_id=module_id)
        and _is_operator_tool_event(e)
    )


def _event_counts_for_mode(e: Dict[str, Any], *, is_lab: bool,
                           module_id: Optional[str] = None) -> bool:
    """Backward-compatible alias for objective completion gating."""
    return _event_counts_for_completion(e, is_lab=is_lab, module_id=module_id)


# Diagnostic reason buckets for events that were observed but NOT counted.
IGNORED_REASONS = (
    "ignored_wrong_path", "ignored_wrong_backend", "ignored_wrong_via",
    "ignored_wrong_module", "ignored_variant_mismatch", "ignored_unknown_reason",
)


def _ignore_reason(e: Dict[str, Any], *, module_id: str, is_lab: bool,
                   module_known_types: set) -> Optional[str]:
    """Why an in-scope event did not count toward this module's progress.

    Returns None when the event counted, or when it is entirely unrelated to
    this module (out-of-scope noise is not reported as an ignore reason).
    """
    et = e.get("event_type")
    in_scope = (et in module_known_types) or (e.get("module_id") == module_id)
    if not in_scope:
        return None

    if module_id == "brute_force":
        counted = _is_brute_force_event_for_completion(e, is_lab=is_lab)
    else:
        counted = _event_counts_for_completion(e, is_lab=is_lab, module_id=module_id)
    if counted:
        return None

    backend = _event_backend(e)
    via = str(e.get("via") or "")
    path = _event_path(e)

    if not is_lab:
        # Defense-in-depth only: compute() short-circuits Guided/Tutorial mode
        # to a reading-only response before this function is ever called with
        # is_lab=False, so this branch is unreachable in the live code path.
        return "ignored_wrong_backend" if backend == "operator" else "ignored_unknown_reason"

    # Lab-mode diagnostics, most-specific first.
    if e.get("module_id") and e.get("module_id") != module_id:
        return "ignored_wrong_module"
    if backend != "operator":
        return "ignored_wrong_backend"
    if et not in DERIVED_EVENT_TYPES and not path.startswith("/op/"):
        return "ignored_wrong_path"
    if via not in _allowed_via_for(module_id):
        return "ignored_wrong_via"
    return "ignored_unknown_reason"


def _is_brute_force_event_for_mode(e: Dict[str, Any], *, is_lab: bool) -> bool:
    if e.get("event_type") not in {
        "login_failed", "login_success", "brute_force_pattern", "credential_found",
    }:
        return False
    path = _event_path(e)
    backend = _event_backend(e)
    if is_lab:
        return (
            path == "/op/auth/login"
            and backend == "operator"
            and _is_operator_tool_event(e)
        )
    return path == "/auth/login" and backend != "operator"


def _is_brute_force_event_for_completion(e: Dict[str, Any], *, is_lab: bool) -> bool:
    if e.get("event_type") in {"login_success", "credential_found"}:
        return _is_brute_force_discovery_event(e, is_lab=is_lab)
    return _is_brute_force_event_for_mode(e, is_lab=is_lab)


def _is_brute_force_event_for_quality(e: Dict[str, Any], *, is_lab: bool) -> bool:
    return _is_brute_force_event_for_mode(e, is_lab=is_lab)


def _is_brute_force_discovery_event(e: Dict[str, Any], *, is_lab: bool) -> bool:
    """Recognize that a valid credential was FOUND, on any channel — including
    the in-lab browser.

    Unlike _is_brute_force_event_for_mode (which gates failures/pattern to the
    approved bulk tools), this accepts a browser login on the operator route as
    proof of discovery. A student who logs in as admin through the browser has
    clearly found the credential. Completion still requires prior tool-driven
    brute-force evidence from the same mission window; Repeater confirmation is
    scored as higher-quality methodology.
    """
    if e.get("event_type") not in {"login_success", "credential_found"}:
        return False
    path = _event_path(e)
    backend = _event_backend(e)
    if is_lab:
        via = str(e.get("via") or "")
        return (
            path == "/op/auth/login"
            and backend == "operator"
            and (via in OPERATOR_TOOL_VIA or via == "browser")
        )
    return path == "/auth/login" and backend != "operator"


def _brute_force_activity(events: List[Dict[str, Any]], *, is_lab: bool) -> Dict[str, Any]:
    scoped = [e for e in events if _is_brute_force_event_for_mode(e, is_lab=is_lab)]
    failures = [e for e in scoped if e.get("event_type") == "login_failed"]
    patterns = [e for e in scoped if e.get("event_type") == "brute_force_pattern"]
    # Credential DISCOVERY is recognized on a wider scope than failures/pattern —
    # a browser login as admin also proves the student found the credential (it
    # just doesn't complete the mission on its own). See _is_brute_force_discovery_event.
    discovery = [e for e in events if _is_brute_force_discovery_event(e, is_lab=is_lab)]
    credentials = [e for e in discovery if e.get("event_type") == "credential_found"]
    successes = [e for e in discovery if e.get("event_type") == "login_success"]
    # Discovery (bulk failures/pattern, or a browser login) can come from any
    # approved completion channel. Repeater confirmation is tracked separately
    # because it improves methodology quality, but it no longer blocks mission
    # completion after real brute-force evidence exists.
    confirmed = [e for e in (credentials + successes) if str(e.get("via") or "") == "zap_repeater"]
    browser_confirmed = [e for e in (credentials + successes) if str(e.get("via") or "") == "browser"]
    paths = sorted({_event_path(e) for e in scoped if _event_path(e)})
    tools = sorted({str(e.get("via")) for e in scoped if str(e.get("via") or "") in OPERATOR_TOOL_VIA})
    return {
        "failed_attempt_count": len(failures),
        "brute_force_pattern_observed": bool(patterns),
        "credential_found": bool(credentials),
        "credential_confirmed": bool(credentials or successes),
        "credential_confirmed_via_repeater": bool(confirmed),
        "credential_confirmed_via_browser": bool(browser_confirmed),
        "required_failed_attempts": BRUTE_FORCE_MIN_FAILURES,
        "path": "/op/auth/login" if is_lab else "/auth/login",
        "paths_observed": paths,
        "tools_observed": tools,
        "first_failed_at": failures[0].get("ts") if failures else None,
        "pattern_observed_at": patterns[-1].get("ts") if patterns else None,
        "credential_found_at": credentials[-1].get("ts") if credentials else None,
        "confirmed_at": (credentials + successes)[-1].get("ts") if (credentials or successes) else None,
        "repeater_confirmed_at": confirmed[-1].get("ts") if confirmed else None,
    }


# ── Per-module success specs ────────────────────────────────────────────────
# Operator (lab) Mode ONLY — Guided/Tutorial Mode is reading-only and never
# reaches this code (compute() short-circuits earlier; see
# `_guided_reading_only_response()`). The legacy `tasks_tutorial` /
# `success_tutorial` ladders were removed as dead code — see
# docs/redteam-guided-mode-reading-only.md.
#
#   tasks_lab — the legacy (non-variant) task ladder for lab mode
#               (AttackBox/ZAP only, via the operator evidence gate).
#   success_lab — event_types that must ALL be observed for the legacy ladder
#                 to be flagged successful. Variant-based missions instead use
#                 OBJECTIVE_SPECS' completion_groups (see below).
PROGRESS_SPECS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "tasks_lab": [
            {
                "title":  "Capture the operator portal",
                "event_types": ["portal_visited"],
                "explain": "Use Browser/ZAP or AttackBox-safe `curl -i http://target-agent/op/` to capture the local /op/ portal.",
            },
            {
                "title":  "Map at least 4 /op/ endpoints with approved tools",
                "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "file_upload_used", "profile_update_used"],
                "min_count": 4,
                "explain": "Use ZAP Repeater/Fuzzer or validator-safe AttackBox requests. Browser clicks help capture traffic, but approved tools complete Operator Mode.",
            },
            {
                "title":  "Discover the hidden lab clue",
                "event_types": ["hidden_clue_accessed", "csrf_lure_visited"],
                "explain": "Replay local discovery paths in ZAP Repeater or validator-safe curl, then compare 200/404 responses carefully.",
            },
            {
                "title":  "Trigger recon sequence detection",
                "event_types": ["recon_sequence_observed"],
                "explain": "After 4+ distinct /op/ areas are observed via approved local tools, this synthetic event fires.",
            },
        ],
        "success_lab":      ["recon_sequence_observed"],
        "defensive_insight":
            "Hide internal route maps from public landing pages. Keep server "
            "version banners out of HTML comments and response headers.",
    },

    "brute_force": {
        "tasks_lab": [
            {
                "title": "Probe the login endpoint with Repeater or safe curl",
                "event_types": ["login_failed", "login_success"],
                "min_count": 1,
                "explain": "Capture POST /op/auth/login in ZAP and send one baseline request through Repeater or a validator-safe AttackBox command.",
            },
            {
                "title": "Run a wordlist attack through approved local tools",
                "event_types": ["login_failed"],
                "min_count": 6,
                "explain": "Drive 6+ login attempts via ZAP Fuzzer, Repeater, or validator-safe AttackBox tooling. Browser clicks do NOT count.",
            },
            {
                "title": "Trigger the brute-force pattern detection",
                "event_types": ["brute_force_pattern"],
                "explain": "After repeated local-tool failures, the pattern event fires.",
            },
            {
                "title": "Confirm a valid credential by hand",
                "event_types": ["credential_found"],
                "explain": "Use the credential found by the local tool run in Repeater or AttackBox and confirm a 302 redirect to /profile/.",
            },
        ],
        "success_lab":      ["login_failed", "credential_found"],
        "defensive_insight":
            "Add per-account and per-IP rate limiting, account lockout after "
            "5 failures, and detection rules for repeated 401 responses.",
    },

    "xss": {
        "tasks_lab": [
            {
                "title": "Capture the search endpoint in ZAP",
                "event_types": ["search_used"],
                "min_count": 1,
                "explain": "Open /op/search, capture GET /op/search?q=..., and inspect where the marker appears in the response.",
            },
            {
                "title": "Submit at least 2 XSS-shaped payloads",
                "event_types": ["xss_payload_observed"],
                "min_count": 2,
                "explain": "Use ZAP Repeater/Fuzzer for event-handler or SVG/IMG payloads. Script tags are stripped on the operator route.",
            },
            {
                "title": "Confirm unescaped reflection",
                "event_types": ["reflected_input_detected"],
                "explain": "Verify a non-script-tag proof payload is reflected unescaped in the response or browser proof.",
            },
        ],
        "success_lab":      ["xss_payload_observed", "reflected_input_detected"],
        "defensive_insight":
            "Encode untrusted output before rendering it into HTML. Use a "
            "templating engine with autoescape ON. Add a CSP that blocks inline scripts.",
    },

    "cmd_injection": {
        "tasks_lab": [
            {
                "title": "Capture the ping endpoint in ZAP",
                "event_types": ["diagnostics_used"],
                "min_count": 1,
                "explain": "Open /op/system/ping with a normal host and send the captured request to Repeater for a clean baseline.",
            },
            {
                "title": "Test 2+ shell metacharacters in ZAP",
                "event_types": ["command_separator_observed"],
                "min_count": 2,
                "explain": "Use ZAP Repeater/Fuzzer for separator payloads. AttackBox intentionally blocks shell-control syntax.",
            },
            {
                "title": "Confirm command-injection proof output",
                "event_types": ["command_injection_detected"],
                "explain": "Use harmless local proof output via Repeater/Fuzzer. Do not use reverse shells, callbacks, deletion, or persistence.",
            },
        ],
        "success_lab":      ["command_injection_detected"],
        "defensive_insight":
            "Never pass user input to shell commands. Use parameterized "
            "system calls (subprocess with a list and shell=False) or a strict "
            "allowlist of legal hostnames.",
    },

    "dir_traversal": {
        "tasks_lab": [
            {
                "title": "Capture the file viewer in ZAP",
                "event_types": ["file_viewer_used"],
                "min_count": 1,
                "explain": "Open /op/files/read?path=readme.txt, capture the request, and send it to Repeater before changing the path parameter.",
            },
            {
                "title": "Test 2+ path variants in ZAP",
                "event_types": ["traversal_pattern_observed"],
                "min_count": 2,
                "explain": "Use Repeater/Fuzzer to compare an allowed file, a rejected traversal pattern, and a local lab disclosure candidate.",
            },
            {
                "title": "Confirm safe lab file disclosure",
                "event_types": ["sensitive_file_disclosed"],
                "explain": "Confirm a local lab file disclosure via approved ZAP tooling. Do not target external or host files.",
            },
        ],
        "success_lab":      ["sensitive_file_disclosed"],
        "defensive_insight":
            "Normalize paths with os.path.realpath and verify the resolved "
            "path stays inside the intended base directory before opening.",
    },

    "file_upload": {
        "tasks_lab": [
            {
                "title": "Capture the upload endpoint in ZAP",
                "event_types": ["file_upload_used"],
                "min_count": 1,
                "explain": "Upload a harmless file in the browser and inspect the multipart POST /op/files/upload in ZAP.",
            },
            {
                "title": "Replay safe multipart uploads",
                "event_types": ["file_saved"],
                "min_count": 2,
                "explain": "Use Repeater to replay or safely edit captured multipart uploads with harmless content.",
            },
            {
                "title": "Demonstrate unsafe upload validation",
                "event_types": ["dangerous_extension_accepted", "unrestricted_upload_detected"],
                "explain": "Use ZAP Repeater/Fuzzer to edit filename or content type with harmless proof content. Do not create or upload a web shell.",
            },
        ],
        "success_lab":      ["unrestricted_upload_detected"],
        "defensive_insight":
            "Validate by file content (magic bytes), enforce an allowlist of "
            "extensions, and never serve uploads from a path that gets executed "
            "by the application server.",
    },

    "csrf": {
        "tasks_lab": [
            {
                "title": "Open the profile page in the browser",
                "event_types": ["profile_update_used"],
                "min_count": 1,
                "explain": "Use the Operator browser and ZAP capture flow for profile state changes; this module is not terminal-command based.",
            },
            {
                "title": "Inspect the profile-update request",
                "event_types": ["profile_update_used"],
                "min_count": 1,
                "explain": "Inspect POST /op/profile/update in ZAP and check whether a CSRF token exists in the form, body, or headers.",
            },
            {
                "title": "Submit the local CSRF lure",
                "event_types": [
                    "csrf_token_missing",
                    "profile_changed_without_csrf",
                ],
                "explain": "Use the local /op/evil/csrf-demo lure and confirm the profile changed without a token. Do not use external exploit servers.",
            },
        ],
        "success_lab":      ["profile_changed_without_csrf"],
        "defensive_insight":
            "Require a CSRF token on every state-changing form, validate the "
            "Origin/Referer header, and use SameSite=Strict cookies.",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE VARIANTS — Each module supports multiple attack flavours.
#  The learner picks one when starting a mission (Operator Mode only).  At
#  progress-compute time the variant's task ladder REPLACES the default
#  tasks_lab for that module, and the variant-specific success markers REPLACE the
#  default ones.  The rest of the spec (defensive_insight etc.) is reused.
#
#  Each variant entry:
#    name         — human-readable name shown in the variant picker
#    description  — 1-2 sentences shown under the radio button
#    difficulty   — "Easy" | "Medium" | "Hard"
#    techniques   — short list of techniques used (informational)
#    tasks        — list of task dicts (same shape as PROGRESS_SPECS.tasks_lab)
#    success_event_types — events that must ALL fire for success
#    ideal_commands — list of literal commands the operator should run
#                     (used by the Report agent for "ideal approach" coaching)
# ═══════════════════════════════════════════════════════════════════════════
MODULE_VARIANTS: Dict[str, Dict[str, Dict[str, Any]]] = {

    # ─── BRUTE FORCE ────────────────────────────────────────────────────
    "brute_force": {
        "password_spray": {
            "name":        "Password Spraying",
            "description": "Try ONE common password across MANY usernames. Evades per-account lockout.",
            "difficulty":  "Easy",
            "techniques":  ["enumeration", "low-and-slow", "single-password"],
            "tasks": [
                {"title": "Enumerate likely usernames",
                 "event_types": ["login_failed", "login_success"],
                 "min_count": 4,
                 "explain":     "Submit at least 4 different usernames with the same trial password."},
                {"title": "Confirm enumeration is blocked (harder backend)",
                 "event_types": ["login_failed"],
                 "min_count": 6,
                 "explain":     "Send at least 6 failed logins across known and unknown usernames. "
                                "The operator backend replies with the same generic 'Invalid credentials' "
                                "401 either way — no wording leak here, so the spray has "
                                "to rely on volume, not response differences."},
                {"title": "Trigger pattern detection",
                 "event_types": ["brute_force_pattern"],
                 "explain":     "Make 3+ failed login attempts from your client — the brute-force "
                                "pattern event fires automatically once the threshold is crossed."},
                {"title": "Discover a working credential",
                 "event_types": ["credential_found"],
                 "explain":     "Keep spraying — one candidate username shares the spray password. "
                                "Completing the mission needs BOTH the pattern (volume) AND a valid login, "
                                "so don't stop at the first success: a real spray is noisy by design."},
            ],
            "success_event_types": ["brute_force_pattern", "credential_found"],
            "ideal_commands": [
                "# ── Password spraying · ZAP Fuzzer (Lab Tools → ZAP → Fuzzer) ──",
                "# Sniper attack: ONE common password, MANY usernames — all on /op/auth/login.",
                "# 1. POSITIONS →  username=§&password=<one common password>   (§ on the username)",
                "# 2. PAYLOADS  →  preset 'Common usernames'  →  START ATTACK",
                "# 3. RESULTS   →  sort by STATUS. The 302 row is the account that reuses it.",
                "# 4. CONFIRM   →  Repeater: resend that username/password → 302 /profile/.",
            ],
        },
        "credential_stuffing": {
            "name":        "Credential Stuffing",
            "description": "Reuse leaked password lists against known accounts. Tests password reuse.",
            "difficulty":  "Medium",
            "techniques":  ["leaked-wordlist", "multi-password", "known-username"],
            "tasks": [
                {"title": "Confirm endpoint accepts repeated POSTs",
                 "event_types": ["login_failed"],
                 "min_count": 1,
                 "explain":     "Send one POST to /op/auth/login to verify the form."},
                {"title": "Stuff a known username with a leaked wordlist",
                 "event_types": ["login_failed"],
                 "min_count": 8,
                 "explain":     "Loop 8+ leaked passwords against username 'admin'."},
                {"title": "Trigger brute-force pattern detection",
                 "event_types": ["brute_force_pattern"],
                 "explain":     "Wazuh-style detection fires after 3+ failures in 5 min."},
                {"title": "Credential found in the leaked list",
                 "event_types": ["credential_found"],
                 "explain":     "The lab passwords contain the planted credential."},
            ],
            "success_event_types": ["brute_force_pattern", "credential_found"],
            "ideal_commands": [
                "# ── Credential stuffing · ZAP Fuzzer ──",
                "#   (Lab Tools → ZAP → Fuzzer.  Attack type: Sniper.  Route: /op/auth/login.)",
                "#",
                "# The operator backend gives an IDENTICAL generic 'Invalid credentials' 401",
                "# for every wrong guess — there is no enumeration signal here, so a grep-match",
                "# phase cannot distinguish a valid username. Instead:",
                "#",
                "# STEP 1 — get the real payload list (built-in presets will NOT work):",
                "#   AttackBox:  cat /lab/operator-passwords.txt",
                "#",
                "# STEP 2 — Sniper the password field, once per candidate username",
                "#   (admin, operator, service — the only three valid accounts):",
                "#   POSITIONS: username=admin&password=§   →  PAYLOADS: paste Step 1's list  →  START ATTACK",
                "#   Repeat with username=operator, then username=service, if the first two don't hit.",
                "#   Read the STATUS column: the 302 row is the working password.",
                "#",
                "# CONFIRM — Repeater: resend the winning username/password → 302 /profile/.",
            ],
        },
        "hydra_targeted": {
            "name":        "Targeted Hydra Attack",
            "description": "Form-aware brute force using hydra with a curated wordlist. Hardest technique. "
                           "(Lab note: this target has no rate-limit/lockout, so the simpler variants also succeed — "
                           "do this one to practise real tooling you'd need against a defended login.)",
            "difficulty":  "Hard",
            "techniques":  ["hydra", "form-template", "parallel-threads"],
            "tasks": [
                {"title": "Inspect the login form structure",
                 "event_types": ["login_failed"],
                 "min_count": 1,
                 "explain":     "GET /op/auth/login and identify the action URL + field names."},
                {"title": "Build a smart wordlist matched to the company",
                 "event_types": ["login_failed"],
                 "min_count": 10,
                 "explain":     "Hydra will probe 10+ password candidates against multiple users."},
                {"title": "Trigger brute-force pattern detection",
                 "event_types": ["brute_force_pattern"],
                 "explain":     "Mass parallel attempts trip the pattern detector instantly."},
                {"title": "Hydra reports a valid credential",
                 "event_types": ["credential_found"],
                 "explain":     "Hydra's -f flag stops on first hit and prints user:pass."},
            ],
            "success_event_types": ["brute_force_pattern", "credential_found"],
            "ideal_commands": [
                "# Advanced track — real CLI tooling. For the GUI-only path, use the",
                "# ZAP Fuzzer instead (Password Spraying / Credential Stuffing variants).",
                "# Hydra form-template against the operator route: path:body:failure-string.",
                "# Use the REAL local wordlist, not a built-in list — cat it first if unsure:",
                "#   cat /lab/operator-passwords.txt",
                "# admin / operator / service are the three valid accounts; -l tries one at a time.",
                "hydra -l admin -P /lab/operator-passwords.txt target-agent http-post-form '/op/auth/login:username=^USER^&password=^PASS^:Invalid credentials' -t 8 -f",
                "# Then confirm the reported credential in ZAP Repeater on /op/auth/login (→ 302 /profile/).",
            ],
        },
    },

    # ─── XSS ────────────────────────────────────────────────────────────
    "xss": {
        "reflected": {
            "name":        "Reflected XSS",
            "description": "Single-request injection — payload bounces back in the response.",
            "difficulty":  "Easy",
            "techniques":  ["reflection", "event-handler", "url-parameter"],
            "tasks": [
                {"title": "Submit a benign query to confirm reflection",
                 "event_types": ["search_used"], "min_count": 1,
                 "explain": "GET /search?q=hello — confirm 'hello' appears in the response body."},
                {"title": "Inject an event-handler payload",
                 "event_types": ["xss_payload_observed"], "min_count": 1,
                 "explain": "Try <img src=x onerror=alert(1)> or <svg onload=alert(1)>; script tags are stripped."},
                {"title": "Confirm the payload renders unescaped",
                 "event_types": ["reflected_input_detected"],
                 "explain": "The response or browser proof shows the event-handler/SVG payload survived."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "# Capture: submit a query in Operator Mode, then open ZAP Proxy History.",
                "# Baseline (AttackBox-safe — no shell metacharacters):",
                "curl -s -G --data-urlencode 'q=hello' http://target-agent/op/search",
                "# ZAP Repeater: set q=<img src=x onerror=alert(1)> and resend on /op/search.",
                "# Confirm: the event-handler payload is reflected unescaped or fires in the browser.",
            ],
        },
        "alternate_context": {
            "name":        "Alternate XSS Contexts",
            "description": "Bypass script-tag blocklists with event handlers and SVG/IMG vectors.",
            "difficulty":  "Medium",
            "techniques":  ["event-handler", "svg-onload", "img-onerror"],
            "tasks": [
                {"title": "Confirm baseline reflection",
                 "event_types": ["search_used"], "min_count": 1,
                 "explain": "GET /search?q=test"},
                {"title": "Submit 3 distinct payload contexts",
                 "event_types": ["xss_payload_observed"], "min_count": 3,
                 "explain": "<img onerror>, <svg onload>, javascript: URL — each is a different filter bypass."},
                {"title": "Confirm at least one unescaped reflection",
                 "event_types": ["reflected_input_detected"],
                 "explain": "Script tags are filtered here; event handlers and SVG/IMG contexts are the bypass."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "# Baseline capture in ZAP Proxy History, then Send to Repeater.",
                "curl -s -G --data-urlencode 'q=test' http://target-agent/op/search",
                "# ZAP Fuzzer: mark the q value and try one payload per request, e.g.:",
                "#   <img src=x onerror=alert(1)>",
                "#   <svg onload=alert(1)>",
                "# Compare responses: the variant reflected unescaped is the working context.",
            ],
        },
        "stored_attempt": {
            "name":        "Stored XSS Probe",
            "description": "Save a payload via the profile bio field — see if it persists. Hardest technique. "
                           "(Lab note: the reflected variant already succeeds here; do this one to learn stored/persistent "
                           "XSS, which is what matters on apps that filter reflected input.)",
            "difficulty":  "Hard",
            "techniques":  ["persistence", "profile-update", "double-trigger"],
            "tasks": [
                {"title": "Authenticate so the profile is editable",
                 "event_types": ["login_success"], "min_count": 1,
                 "explain": "POST /auth/login with valid credentials."},
                {"title": "Submit a payload through the profile bio",
                 "event_types": ["xss_payload_observed", "profile_update_used"], "min_count": 2,
                 "explain": "POST /profile/update with email or bio containing a harmless event-handler payload."},
                {"title": "Verify the payload reflects on a SECOND request",
                 "event_types": ["reflected_input_detected"],
                 "explain": "Reload /profile/ and confirm the payload is still there."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "# 1. Authenticate on the operator surface (use the lab-provided credential).",
                "# 2. ZAP Repeater: POST /op/profile/update with a harmless event-handler payload in the email field.",
                "# 3. Re-request /op/profile/ in Repeater and confirm the payload persists unescaped.",
            ],
        },
    },

    # ─── COMMAND INJECTION ──────────────────────────────────────────────
    "cmd_injection": {
        "semicolon_basic": {
            "name":        "Semicolon Chaining",
            "description": "Classic shell-injection: append a second command with ;.",
            "difficulty":  "Easy",
            "techniques":  ["semicolon", "command-chaining"],
            "tasks": [
                {"title": "Confirm the ping endpoint works",
                 "event_types": ["diagnostics_used"], "min_count": 1,
                 "explain": "GET /system/ping?host=127.0.0.1"},
                {"title": "Submit a semicolon-chained payload",
                 "event_types": ["command_separator_observed"], "min_count": 1,
                 "explain": "host=127.0.0.1; id"},
                {"title": "Confirm the injected command ran",
                 "event_types": ["command_injection_detected"],
                 "explain": "Output contains 'uid=' or '/etc/' indicators."},
            ],
            "success_event_types": ["command_injection_detected"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe — a clean host value, no separators):",
                "curl -s -G --data-urlencode 'host=localhost' http://target-agent/op/system/ping",
                "# ZAP Repeater: change host to  127.0.0.1; id  and resend on /op/system/ping.",
                "# Confirm: command output such as uid= appears after the ping output.",
            ],
        },
        "pipe_redirect": {
            "name":        "Pipe & Redirect",
            "description": "Bypass semicolon filters using | and > characters.",
            "difficulty":  "Medium",
            "techniques":  ["pipe", "redirect", "filter-bypass"],
            "tasks": [
                {"title": "Probe the endpoint",
                 "event_types": ["diagnostics_used"], "min_count": 1,
                 "explain": "GET /system/ping?host=127.0.0.1"},
                {"title": "Test 2+ alternative separators",
                 "event_types": ["command_separator_observed"], "min_count": 2,
                 "explain": "Try host=127.0.0.1|whoami, host=127.0.0.1>/tmp/out.txt"},
                {"title": "Confirm RCE through pipe",
                 "event_types": ["command_injection_detected"],
                 "explain": "Pipe output reveals system info."},
            ],
            "success_event_types": ["command_injection_detected"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe):",
                "curl -s -G --data-urlencode 'host=localhost' http://target-agent/op/system/ping",
                "# ZAP Fuzzer: mark the host value and test one separator per request, e.g.:",
                "#   127.0.0.1|whoami",
                "#   127.0.0.1 && cat /etc/hostname",
                "# Compare responses to see which separator the backend accepts.",
            ],
        },
        "subshell": {
            "name":        "Subshell Substitution",
            "description": "Use $() or backticks to inject output. Stealthy — no obvious separator. Hardest technique. "
                           "(Lab note: the semicolon variant already works here; do this one to learn a bypass that "
                           "survives filters which only block ; and |.)",
            "difficulty":  "Hard",
            "techniques":  ["subshell", "backtick", "dollar-paren"],
            "tasks": [
                {"title": "Confirm baseline",
                 "event_types": ["diagnostics_used"], "min_count": 1,
                 "explain": "GET /system/ping?host=127.0.0.1"},
                {"title": "Inject via $(...) or `...`",
                 "event_types": ["command_separator_observed"], "min_count": 2,
                 "explain": "host=$(id), host=`whoami`"},
                {"title": "Confirm subshell output reached you",
                 "event_types": ["command_injection_detected"],
                 "explain": "Response shows command output substituted into ping target."},
            ],
            "success_event_types": ["command_injection_detected"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe):",
                "curl -s -G --data-urlencode 'host=localhost' http://target-agent/op/system/ping",
                "# ZAP Repeater: test a subshell payload in the host value, e.g.  127.0.0.1$(id)",
                "# Confirm: the substituted command output appears in the response.",
            ],
        },
    },

    # ─── DIR TRAVERSAL ──────────────────────────────────────────────────
    "dir_traversal": {
        "plain": {
            "name":        "Plain ../",
            "description": "Vanilla path traversal — no encoding, no tricks.",
            "difficulty":  "Easy",
            "techniques":  ["dotdotslash", "relative-path"],
            "tasks": [
                {"title": "Probe the file viewer",
                 "event_types": ["file_viewer_used"], "min_count": 1,
                 "explain": "GET /files/read?path=readme.txt"},
                {"title": "Submit a traversal sequence",
                 "event_types": ["traversal_pattern_observed"], "min_count": 1,
                 "explain": "path=../../etc/passwd"},
                {"title": "Read a sensitive system file",
                 "event_types": ["sensitive_file_disclosed"],
                 "explain": "Response contains 'root:' or '/bin/bash'."},
            ],
            "success_event_types": ["sensitive_file_disclosed"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe — a normal file):",
                "curl -s http://target-agent/op/files/read",
                "# ZAP Repeater: change path to  ../../etc/passwd  and resend on /op/files/read.",
                "# Confirm: the response body contains a passwd-style 'root:' line.",
            ],
        },
        "encoded": {
            "name":        "URL-Encoded Traversal",
            "description": "Bypass simple string filters with %2e and %2f.",
            "difficulty":  "Medium",
            "techniques":  ["url-encoding", "filter-bypass"],
            "tasks": [
                {"title": "Probe the viewer",
                 "event_types": ["file_viewer_used"], "min_count": 1,
                 "explain": "GET /files/read?path=readme.txt"},
                {"title": "Submit 2+ encoded traversal variants",
                 "event_types": ["traversal_pattern_observed"], "min_count": 2,
                 "explain": "%2e%2e%2fetc%2fpasswd, also try %252e%252e for double-encoding."},
                {"title": "Disclose a sensitive file",
                 "event_types": ["sensitive_file_disclosed"],
                 "explain": "Response includes /etc/passwd content."},
            ],
            "success_event_types": ["sensitive_file_disclosed"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe):",
                "curl -s http://target-agent/op/files/read",
                "# ZAP Fuzzer: mark the path value and test encoded traversal variants, e.g.:",
                "#   ..%2F..%2Fetc%2Fpasswd",
                "#   %252E%252E%252Fetc%252Fpasswd  (double-encoded)",
                "# Confirm: a passwd-style file is disclosed in the response.",
            ],
        },
        "absolute": {
            "name":        "Absolute Path",
            "description": "Skip the traversal — just send /etc/passwd directly. Hardest technique. "
                           "(Lab note: plain ../ already works here; do this one to learn the bypass for apps that "
                           "strip ../ sequences but forget to block absolute paths.)",
            "difficulty":  "Hard",
            "techniques":  ["absolute-path", "null-byte"],
            "tasks": [
                {"title": "Probe the viewer",
                 "event_types": ["file_viewer_used"], "min_count": 1,
                 "explain": "GET /files/read?path=readme.txt"},
                {"title": "Submit an absolute path",
                 "event_types": ["traversal_pattern_observed"], "min_count": 1,
                 "explain": "path=/etc/passwd (no dot-dot)."},
                {"title": "Disclose sensitive file via absolute path",
                 "event_types": ["sensitive_file_disclosed"],
                 "explain": "Some apps strip ../ but accept absolute paths."},
            ],
            "success_event_types": ["sensitive_file_disclosed"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe):",
                "curl -s http://target-agent/op/files/read",
                "# ZAP Repeater: set path to an absolute path such as /etc/passwd (no ../).",
                "# The operator route strips '..' but still accepts absolute paths — that is the bypass.",
                "# Confirm: the response body contains a passwd-style 'root:' line.",
            ],
        },
    },

    # ─── FILE UPLOAD ────────────────────────────────────────────────────
    "file_upload": {
        "wrong_extension": {
            "name":        "Dangerous Extension",
            "description": "Upload a .php or .sh file — the simplest test of upload validation.",
            "difficulty":  "Easy",
            "techniques":  ["extension-bypass"],
            "tasks": [
                {"title": "Submit a benign file",
                 "event_types": ["file_upload_used", "file_saved"], "min_count": 2,
                 "explain": "Upload probe.txt to confirm the endpoint works."},
                {"title": "Upload a .php file",
                 "event_types": ["dangerous_extension_accepted"], "min_count": 1,
                 "explain": "Upload shell.php — confirm the server stores it."},
                {"title": "Confirm unrestricted upload",
                 "event_types": ["unrestricted_upload_detected"],
                 "explain": "Server returns a path under /static/uploads/."},
            ],
            "success_event_types": ["unrestricted_upload_detected"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe — upload a harmless local file):",
                "curl -F 'file=@/etc/hostname' http://target-agent/op/files/upload",
                "# ZAP Repeater: replay the multipart upload with a bypass extension the",
                "# operator filter misses (e.g. .phtml / .svg / .html) — never a real web shell.",
                "# Confirm: the server stores the file and returns a /static/uploads/ path.",
            ],
        },
        "mime_spoof": {
            "name":        "MIME Type Spoofing",
            "description": "Lie about the file type via Content-Type header.",
            "difficulty":  "Medium",
            "techniques":  ["mime-confusion", "content-type-bypass"],
            "tasks": [
                {"title": "Upload a normal image",
                 "event_types": ["file_saved"], "min_count": 1,
                 "explain": "Upload a real image to confirm baseline."},
                {"title": "Upload a .php disguised as image/png",
                 "event_types": ["dangerous_extension_accepted"], "min_count": 1,
                 "explain": "curl -F 'file=@shell.php;type=image/png' — see if server trusts the header."},
                {"title": "Confirm unrestricted upload",
                 "event_types": ["unrestricted_upload_detected"],
                 "explain": "Server returns a path — MIME wasn't enforced."},
            ],
            "success_event_types": ["unrestricted_upload_detected"],
            "ideal_commands": [
                "# Baseline (AttackBox-safe):",
                "curl -F 'file=@/etc/hostname' http://target-agent/op/files/upload",
                "# ZAP Repeater: replay the upload but change the file part's Content-Type",
                "# to image/png while keeping a bypass extension. Use a harmless proof file only.",
                "# Confirm: the server accepts it despite the mismatched type.",
            ],
        },
        "polyglot": {
            "name":        "Polyglot File",
            "description": "Valid image AND valid script in the same file. Bypasses content-sniffing. Hardest technique. "
                           "(Lab note: a plain .php already uploads here; do this one to learn the bypass for servers "
                           "that validate magic bytes / MIME.)",
            "difficulty":  "Hard",
            "techniques":  ["polyglot", "magic-bytes", "double-format"],
            "tasks": [
                {"title": "Upload a baseline file",
                 "event_types": ["file_saved"], "min_count": 1,
                 "explain": "Confirm the endpoint accepts uploads."},
                {"title": "Upload a polyglot (.jpg.php)",
                 "event_types": ["dangerous_extension_accepted"], "min_count": 1,
                 "explain": "Prepend JPEG magic bytes to a PHP payload, save as .jpg.php"},
                {"title": "Confirm unrestricted upload",
                 "event_types": ["unrestricted_upload_detected"],
                 "explain": "Both content sniffing AND extension check fail."},
            ],
            "success_event_types": ["unrestricted_upload_detected"],
            "ideal_commands": [
                "# ZAP Repeater: replay the multipart upload with a harmless polyglot proof",
                "# file — valid image magic bytes plus a benign marker, saved with a bypass",
                "# extension such as .jpg.phtml. Do NOT use a real web shell.",
                "# Confirm: both the content sniff and the extension check are bypassed.",
            ],
        },
    },

    # ─── CSRF ───────────────────────────────────────────────────────────
    "csrf": {
        "basic_forgery": {
            "name":        "Basic Forgery",
            "description": "Submit a state-changing POST without a CSRF token from any origin.",
            "difficulty":  "Easy",
            "techniques":  ["missing-token", "post-forgery"],
            "tasks": [
                {"title": "Login and capture cookie",
                 "event_types": ["login_success"], "min_count": 1,
                 "explain": "POST /auth/login with valid creds, save cookies."},
                {"title": "Submit /profile/update without a token",
                 "event_types": ["profile_update_used", "csrf_token_missing"], "min_count": 2,
                 "explain": "POST -d 'email=pwned@evil.lab' with the cookie."},
                {"title": "Confirm profile was changed",
                 "event_types": ["profile_changed_without_csrf"],
                 "explain": "GET /profile/ shows the new email."},
            ],
            "success_event_types": ["profile_changed_without_csrf"],
            "ideal_commands": [
                "# 1. Authenticate on the operator surface (use the lab-provided credential).",
                "# 2. ZAP Repeater: POST /op/profile/update with a new email and NO CSRF token.",
                "# 3. Re-request /op/profile/ in Repeater and confirm the email changed.",
            ],
        },
        "lure_page": {
            "name":        "Attacker Lure Page",
            "description": "Use the /evil/csrf-demo lure — simulates a real cross-site attack.",
            "difficulty":  "Medium",
            "techniques":  ["lure-page", "auto-submit", "referer-spoof"],
            "tasks": [
                {"title": "Login as victim",
                 "event_types": ["login_success"], "min_count": 1,
                 "explain": "Authenticate as admin."},
                {"title": "Visit the attacker lure page",
                 "event_types": ["csrf_lure_visited"], "min_count": 1,
                 "explain": "GET /evil/csrf-demo (the in-lab attacker page)."},
                {"title": "Confirm the forged update succeeded",
                 "event_types": ["csrf_lure_submitted", "profile_changed_without_csrf"], "min_count": 2,
                 "explain": "The lure auto-submits — profile email changes silently."},
            ],
            "success_event_types": ["csrf_lure_submitted", "profile_changed_without_csrf"],
            "ideal_commands": [
                "# 1. Authenticate on the operator surface as the victim.",
                "# 2. In the ZAP-routed lab browser, open the local lure /op/evil/csrf-demo.",
                "# 3. The lure auto-submits to /op/profile/update — confirm the email changed silently.",
            ],
        },
        "json_bypass": {
            "name":        "Content-Type Bypass",
            "description": "Send the request as JSON — many anti-CSRF filters only check form posts. Hardest technique. "
                           "(Lab note: basic form forgery already works here; do this one to learn the bypass for apps "
                           "that add CSRF protection but only enforce it on form-encoded posts.)",
            "difficulty":  "Hard",
            "techniques":  ["content-type-confusion", "json-body"],
            "tasks": [
                {"title": "Login",
                 "event_types": ["login_success"], "min_count": 1,
                 "explain": "Standard auth."},
                {"title": "Submit profile-update as application/json",
                 "event_types": ["profile_update_used"], "min_count": 1,
                 "explain": "curl -H 'Content-Type: application/json' -d '{\"email\":\"pwned@evil.lab\"}'"},
                {"title": "Confirm the change persisted",
                 "event_types": ["profile_changed_without_csrf"],
                 "explain": "Read profile back — confirm the JSON body was accepted."},
            ],
            "success_event_types": ["profile_changed_without_csrf"],
            "ideal_commands": [
                "# 1. Authenticate on the operator surface (use the lab-provided credential).",
                "# 2. ZAP Repeater: POST /op/profile/update with Content-Type application/json",
                "#    and a JSON body such as {\"email\":\"pwned@lab.local\"} — no CSRF token.",
                "# 3. Re-request /op/profile/ and confirm the JSON body was accepted.",
            ],
        },
    },

    # ─── RECON ──────────────────────────────────────────────────────────
    "recon": {
        "manual": {
            "name":        "Manual Walking",
            "description": "Click through the portal and read what you find. Easy entry-level recon.",
            "difficulty":  "Easy",
            "techniques":  ["manual-browsing", "html-inspection"],
            "tasks": [
                {"title": "Visit the portal home",
                 "event_types": ["portal_visited"], "min_count": 1,
                 "explain": "GET /"},
                {"title": "Visit at least 3 application areas",
                 "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "file_upload_used", "profile_update_used"],
                 "min_count": 3,
                 "explain": "Walk through the obvious links from the home page."},
                {"title": "Trigger the recon-sequence detector",
                 "event_types": ["recon_sequence_observed"],
                 "explain": "4+ distinct areas visited fires this synthetic event."},
            ],
            "success_event_types": ["recon_sequence_observed"],
            "ideal_commands": [
                "# Map the operator portal with AttackBox-safe single requests:",
                "curl -s -i http://target-agent/op/",
                "curl -s -i http://target-agent/op/search?q=test",
                "curl -s -i http://target-agent/op/files/read?path=readme.txt",
                "# Visit 4+ distinct /op/ areas to trip the recon-sequence detector.",
            ],
        },
        "wordlist": {
            "name":        "Wordlist Enumeration",
            "description": "Use gobuster/ffuf to discover hidden paths not on the home page.",
            "difficulty":  "Medium",
            "techniques":  ["wordlist", "gobuster", "directory-brute"],
            "tasks": [
                {"title": "Confirm the target responds",
                 "event_types": ["portal_visited"], "min_count": 1,
                 "explain": "curl -i http://target-agent/"},
                {"title": "Enumerate 4+ endpoints with a wordlist",
                 "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "file_upload_used", "profile_update_used"],
                 "min_count": 4,
                 "explain": "Run gobuster against the host with common.txt."},
                {"title": "Find a hidden route or clue",
                 "event_types": ["hidden_clue_accessed", "csrf_lure_visited"],
                 "explain": "Wordlist finds /evil/csrf-demo or /robots.txt."},
            ],
            "success_event_types": ["recon_sequence_observed"],
            "ideal_commands": [
                "# Content discovery against the operator surface (single, safe invocations):",
                "gobuster dir -u http://target-agent/op/ -w /usr/share/wordlists/dirb/common.txt -t 20 -q",
                "ffuf -w /wordlists/routes.txt -u http://target-agent/op/FUZZ",
                "# Then request each discovered /op/ path in ZAP Repeater to verify it.",
            ],
        },
        "comment_hunting": {
            "name":        "HTML Comment Hunting",
            "description": "Read source HTML/JS for developer mistakes — comments, version banners. Hardest technique. "
                           "(Lab note: manual/wordlist recon already maps the app; do this one to practise spotting "
                           "leaked hints in source that automated tools skip over.)",
            "difficulty":  "Hard",
            "techniques":  ["html-comment-grep", "version-disclosure"],
            "tasks": [
                {"title": "Fetch the portal home",
                 "event_types": ["portal_visited"], "min_count": 1,
                 "explain": "curl -s http://target-agent/"},
                {"title": "Grep for comments and version banners",
                 "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "profile_update_used"],
                 "min_count": 2,
                 "explain": "curl -s ... | grep -E '<!--|Server:|version'"},
                {"title": "Discover a hidden clue",
                 "event_types": ["hidden_clue_accessed", "csrf_lure_visited"],
                 "explain": "Comments often leak admin URLs or framework versions."},
            ],
            "success_event_types": ["recon_sequence_observed"],
            "ideal_commands": [
                "# Fetch the operator home and read the raw HTML source in ZAP Inspector:",
                "curl -s -i http://target-agent/op/",
                "# Look in the response for HTML comments, Server/version banners, and href targets.",
                "# Follow any leaked path (e.g. /op/.git/config) and verify it in ZAP Repeater.",
            ],
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════
#  WALKTHROUGH — TryHackMe-style teaching content per variant.
#
#  For each (module_id, variant_id) we provide:
#    overview  — 2-4 sentences: what this attack is + how it works overall.
#    sections  — list aligned BY INDEX with the variant's `tasks`. Each:
#        what     — what this step is / the concept behind it
#        how      — how it's actually done (method + concrete command)
#        look_for — the observable signal that proves the step worked
#
#  compute() merges these into each task so the guided UI can render a
#  rich, explained walkthrough. Modules without an entry here gracefully
#  fall back to the task's one-line `explain`.
# ═══════════════════════════════════════════════════════════════════════════
WALKTHROUGH: Dict[str, Dict[str, Dict[str, Any]]] = {

    # ─── BRUTE FORCE ────────────────────────────────────────────────────
    "brute_force": {
        "password_spray": {
            "overview": (
                "Password spraying flips a normal brute-force on its head: instead of "
                "hammering one account with thousands of passwords (which trips lockouts), "
                "you try ONE very common password against MANY usernames. Because each "
                "account only sees a single failed attempt, per-account lockout never "
                "fires — yet across a big enough user list, someone is always reusing "
                "'password123'."
            ),
            "sections": [
                {
                    "what": "Before you can spray, you need a list of usernames that probably exist. "
                            "Most apps leak this via predictable names (admin, operator, service) or "
                            "different responses for valid vs invalid users — though this target's "
                            "operator backend deliberately hides that second signal (see next step).",
                    "how":  "Submit a handful of likely usernames with a throwaway password through the "
                            "lab browser — each POST to /op/auth/login shows up in ZAP Proxy History. "
                            "Try admin, operator, guest, alice, bob, service — one wrong password each.",
                    "look_for": "Each attempt is logged as a failed login (a normal 401 with a generic "
                                "error body). 4+ distinct usernames marks this step done.",
                },
                {
                    "what": "On many apps, different error wording between valid and invalid users "
                            "leaks which accounts exist. This operator backend was hardened specifically "
                            "to remove that leak.",
                    "how":  "Compare the response across attempts for a username you believe is real "
                            "(admin) and an obviously fake one (zzqq). Both return the identical generic "
                            "'Invalid credentials' 401 — no enumeration channel here.",
                    "look_for": "Same status and message on every attempt = enumeration is blocked. "
                                "6+ attempts marks this done.",
                },
                {
                    "what": "Repeated failed logins from one source are exactly what a SOC watches for. "
                            "This step proves the attack is noisy and detectable — the blue-team side of the lesson.",
                    "how":  "Keep spraying. After 3+ failures from your IP inside the detection window, "
                            "the lab fires a synthetic brute-force-pattern event (mirrors a Wazuh rule).",
                    "look_for": "A 'Brute-force pattern detected' evidence card appears in the panel.",
                },
                {
                    "what": "The payoff: one of your sprayed users shares the common password. "
                            "That single 302 redirect is a full account takeover.",
                    "how":  "When a sprayed username returns success (redirect to /profile/ instead of the "
                            "usual 401 'Invalid credentials' page), you've found a live credential. Only "
                            "admin, operator, and service are real accounts on this backend.",
                    "look_for": "A 'Valid credential confirmed' card — you successfully logged in.",
                },
            ],
        },
        "credential_stuffing": {
            "overview": (
                "Credential stuffing assumes people reuse passwords. Attackers take "
                "username/password pairs leaked from OTHER breaches and replay them against "
                "your login. You're not guessing randomly — you're betting that a known user "
                "reused a password that already appeared in a public dump like rockyou.txt."
            ),
            "sections": [
                {
                    "what": "First confirm the login endpoint accepts repeated automated POSTs with no "
                            "rate limit, CAPTCHA, or lockout — the precondition that makes stuffing viable.",
                    "how":  "Send one login POST to /op/auth/login (any password) through the lab browser "
                            "or ZAP Repeater and confirm you get a clean 401 back with a "
                            "generic 'Invalid credentials' body, not a block or challenge.",
                    "look_for": "A failed-login event is recorded — the endpoint is reachable and unprotected.",
                },
                {
                    "what": "Now replay a leaked password list against a known account. This is the heart of "
                            "stuffing: a curated wordlist of real, previously-breached passwords. The default "
                            "wordlist presets won't hit here — this backend's passwords aren't in rockyou-mini.",
                    "how":  "Get the real seed list on the AttackBox (`cat /lab/operator-passwords.txt`), then "
                            "in ZAP Fuzzer: POSITIONS username=admin&password=§ → PAYLOADS paste that list → "
                            "START ATTACK on /op/auth/login.",
                    "look_for": "8+ failed-login attempts recorded against admin marks this step done.",
                },
                {
                    "what": "High-volume automated attempts trip detection. Again this shows the defensive "
                            "signal a real SOC would alert on.",
                    "how":  "The wordlist loop itself produces enough failures (3+ in the window) to fire "
                            "the brute-force-pattern detection.",
                    "look_for": "A 'Brute-force pattern detected' evidence card appears.",
                },
                {
                    "what": "If the reused password is anywhere in the leaked list, you're in — without ever "
                            "'guessing'. That's why password reuse is so dangerous.",
                    "how":  "Sort the Fuzzer results by STATUS — the 302 row is the hit. If admin doesn't hit, "
                            "repeat with username=operator, then username=service (the only three valid "
                            "accounts). Confirm the winner in Repeater: resend it → 302 redirect to /profile/.",
                    "look_for": "A 'Valid credential confirmed' card — the leaked password worked.",
                },
            ],
        },
        "hydra_targeted": {
            "overview": (
                "This is brute-force done with a real tool. THC-Hydra understands HTTP login "
                "forms: you describe the form (URL, fields, and the failure string), hand it a "
                "wordlist, and it submits attempts in parallel and stops on the first success. "
                "It's the fastest, loudest variant — and the most realistic to how forms get cracked."
            ),
            "sections": [
                {
                    "what": "Hydra needs to know exactly how the form works: the path it POSTs to, the field "
                            "names, and the text that appears on a FAILED login (so it can tell success from "
                            "failure). Note: this backend returns a normal 401 on a denied login. Hydra's "
                            "http-post-form module can misread a 401 as HTTP Basic Auth and stop evaluating "
                            "the failure string — if it loops, switch to the ZAP Fuzzer (sort by status: "
                            "401 = wrong, 302 = the hit), which reads this backend cleanly.",
                    "how":  "GET /op/auth/login and read the HTML form. Identify action=/op/auth/login, fields "
                            "username & password, and the generic failure message ('Invalid credentials').",
                    "look_for": "One probe login is recorded — you've confirmed the form's shape.",
                },
                {
                    "what": "The built-in wordlist presets won't work — this backend's passwords aren't in "
                            "rockyou-mini. You need the real seed list mounted on the AttackBox.",
                    "how":  "Get the list first (`cat /lab/operator-passwords.txt`), then run Hydra with the "
                            "http-post-form module: "
                            "`hydra -l admin -P /lab/operator-passwords.txt target-agent http-post-form "
                            "'/op/auth/login:username=^USER^&password=^PASS^:Invalid credentials' -t 8 -f`. "
                            "Repeat with -l operator, then -l service, if admin doesn't hit.",
                    "look_for": "10+ login attempts recorded as Hydra works through the list.",
                },
                {
                    "what": "Hydra's parallel threads create a burst of failures — the most obvious detection "
                            "signature of all three variants.",
                    "how":  "The mass parallel attempts (-t 8) trip the brute-force-pattern detector almost immediately.",
                    "look_for": "A 'Brute-force pattern detected' evidence card appears.",
                },
                {
                    "what": "With -f, Hydra halts on the first valid pair and prints it. That's your credential, "
                            "found automatically.",
                    "how":  "Read Hydra's output line: [80][http-post-form] host: target-agent login: <user> "
                            "password: <pass>. Verify it in ZAP Repeater on /op/auth/login → 302 to /profile/.",
                    "look_for": "A 'Valid credential confirmed' card — Hydra cracked the login.",
                },
            ],
        },
    },

    # ─── XSS ────────────────────────────────────────────────────────────
    "xss": {
        "reflected": {
            "overview": (
                "Reflected XSS happens when an app takes input from the request (like a search "
                "query) and writes it straight back into the HTML response without escaping it. "
                "The operator route strips script tags, so the useful proof is an alternate browser "
                "execution context such as an image error handler or SVG onload. It's 'reflected' "
                "because the payload bounces back in the same single response."
            ),
            "sections": [
                {
                    "what": "Reflection is the precondition for this attack: your input must appear somewhere "
                            "in the response. First prove the search box echoes what you type.",
                    "how":  "Search for a unique marker like 'attense_probe'. In the lab browser: "
                            "/search?q=attense_probe — then look for that word in the results.",
                    "look_for": "Your marker appears in the page — input is reflected. (search_used event)",
                },
                {
                    "what": "Now test whether HTML/event-handler markup survives the filter. A raw script tag "
                            "is stripped here, so use a browser execution context the filter misses.",
                    "how":  "Submit an event-handler payload such as /search?q=<img src=x onerror=alert(1)> "
                            "or /search?q=<svg onload=alert(1)> (URL-encode if typing in a terminal).",
                    "look_for": "An 'XSS-shaped payload submitted' card — the app received your proof payload.",
                },
                {
                    "what": "Confirmation: the payload is reflected unescaped, meaning a real browser would "
                            "execute it. That's a working reflected XSS.",
                    "how":  "Check the response body or browser proof shows the event-handler/SVG payload "
                            "survived sanitization without entity encoding.",
                    "look_for": "A 'Reflected input observed' card — the payload rendered unescaped.",
                },
            ],
        },
        "alternate_context": {
            "overview": (
                "Real apps often block the obvious <script> tag. Alternate-context XSS bypasses "
                "those naive filters using other ways browsers run JavaScript: event handlers "
                "(onerror, onload) on image/SVG tags, or javascript: URLs. The lesson: blocklists "
                "are brittle — there are dozens of sinks, and you only need one to survive filtering."
            ),
            "sections": [
                {
                    "what": "Start by confirming the endpoint still reflects input, so you know any failure "
                            "later is the filter, not a dead endpoint.",
                    "how":  "Submit a harmless query: /search?q=test and confirm it's echoed.",
                    "look_for": "Input is reflected. (search_used event)",
                },
                {
                    "what": "Try several different execution contexts. Each is a distinct filter bypass: "
                            "an <img> with onerror, an <svg> with onload, and a breakout from an attribute.",
                    "how":  "Submit three payloads: <img src=x onerror=alert(1)>, <svg onload=alert(1)>, "
                            "and <a href=javascript:alert(1)>x</a> — one at a time.",
                    "look_for": "3 'XSS-shaped payload submitted' cards — you tested multiple vectors.",
                },
                {
                    "what": "Even if <script> is filtered, an event handler usually slips through. Confirm at "
                            "least one of your vectors reflected unescaped.",
                    "how":  "Inspect each response — find the payload that came back intact (e.g. the onerror "
                            "handler) while others were stripped.",
                    "look_for": "A 'Reflected input observed' card — a bypass succeeded.",
                },
            ],
        },
        "stored_attempt": {
            "overview": (
                "Stored XSS is the dangerous cousin of reflected XSS: instead of bouncing back in "
                "one response, the payload is SAVED by the app (in a profile bio, a comment, a name) "
                "and runs every time anyone views that page. One injection, many victims, no link to "
                "click. Here you'll try to persist a payload through the profile and see it fire on a "
                "second, separate request."
            ),
            "sections": [
                {
                    "what": "Stored XSS needs a place to store data. Authenticate so you can edit a persistent "
                            "field — your profile.",
                    "how":  "Log in with valid credentials (admin:password123) so the profile becomes editable.",
                    "look_for": "A 'Successful login observed' card.",
                },
                {
                    "what": "Inject the payload into a field that gets saved and re-displayed, like the profile "
                            "email/bio — not just a transient search box.",
                    "how":  "POST /profile/update with a harmless event-handler payload in the email/bio field, e.g. "
                            "bio=<img src=x onerror=alert(1)>.",
                    "look_for": "Both a payload-submitted and profile-update event (2 events) mark this done.",
                },
                {
                    "what": "The defining test of STORED XSS: the payload must reappear on a fresh page load, "
                            "proving it was persisted server-side rather than just reflected.",
                    "how":  "Reload /profile/ in a new request and check the saved payload is still there, unescaped.",
                    "look_for": "A 'Reflected input observed' card on the second request — the payload persisted.",
                },
            ],
        },
    },

    # ─── COMMAND INJECTION ──────────────────────────────────────────────
    "cmd_injection": {
        "semicolon_basic": {
            "overview": (
                "Command injection happens when an app builds an OS shell command out of user "
                "input and runs it. The /system/ping diagnostics page takes a host and runs "
                "`ping <host>` on the server. Because the shell treats ';' as 'end this command, "
                "start another', you can append your OWN command after the host and the server "
                "runs both — giving you code execution as the web process."
            ),
            "sections": [
                {
                    "what": "First understand normal behaviour: the page runs ping against whatever host "
                            "you give it and shows the output. That output channel is how you'll read your results.",
                    "how":  "Submit a legitimate host in the lab browser: /system/ping?host=127.0.0.1 and read "
                            "the ping reply that comes back.",
                    "look_for": "A 'Diagnostics form used' card — the endpoint accepted your input.",
                },
                {
                    "what": "The semicolon is a shell command separator. If the app doesn't strip it, "
                            "everything after it runs as a brand-new command.",
                    "how":  "Append a second command: host=127.0.0.1; id  (use the address bar or curl "
                            "--data-urlencode 'host=127.0.0.1; id').",
                    "look_for": "A 'Shell metacharacters observed' card — your separator reached the shell.",
                },
                {
                    "what": "Proof of execution: the output of your injected command (not the ping) appears "
                            "in the response. Seeing `uid=` means you ran `id` on the server.",
                    "how":  "Look at the response for command output like 'uid=0(root)' or contents of /etc/passwd.",
                    "look_for": "A 'Command injection confirmed' card — your command executed.",
                },
            ],
        },
        "pipe_redirect": {
            "overview": (
                "Some apps blocklist the semicolon, so you reach for other shell operators. The "
                "pipe '|' sends ping's output into another command, '&&' chains a command that runs "
                "if the first succeeds, and '>' redirects output to a file. Each is a different way "
                "to smuggle execution past a naive filter that only looked for ';'."
            ),
            "sections": [
                {
                    "what": "Re-establish the baseline so any later failure is clearly the filter, not a broken page.",
                    "how":  "Submit /system/ping?host=127.0.0.1 and confirm a normal ping response.",
                    "look_for": "A 'Diagnostics form used' card.",
                },
                {
                    "what": "Try operators other than ';'. Pipe (|) and AND (&&) are classic semicolon-filter "
                            "bypasses — you only need one to get through.",
                    "how":  "Test two: host=127.0.0.1|whoami  and  host=127.0.0.1 && cat /etc/hostname "
                            "(URL-encode when using curl).",
                    "look_for": "A 'Shell metacharacters observed' card — an alternative separator slipped past the filter.",
                },
                {
                    "what": "Confirm code execution through the operator that survived — the injected command's "
                            "output is in the response.",
                    "how":  "Read the response for the output of whoami / cat (e.g. a username or hostname).",
                    "look_for": "A 'Command injection confirmed' card.",
                },
            ],
        },
        "subshell": {
            "overview": (
                "The stealthiest variant uses command substitution: $(...) or backticks `...`. The "
                "shell runs what's inside FIRST and substitutes the result into the outer command — "
                "no obvious separator like ; or | for a filter to catch. It's the kind of payload "
                "that bypasses blocklists built only around separator characters."
            ),
            "sections": [
                {
                    "what": "Confirm the endpoint behaves normally before introducing substitution.",
                    "how":  "Submit /system/ping?host=127.0.0.1.",
                    "look_for": "A 'Diagnostics form used' card.",
                },
                {
                    "what": "Inject with substitution. $(id) or `whoami` is evaluated by the shell and its output "
                            "becomes the 'host' that ping tries to resolve — leaking the result back to you.",
                    "how":  "Try two forms: host=$(id)  and  host=`whoami`  (URL-encode the special characters).",
                    "look_for": "A 'Shell metacharacters observed' card — the substitution reached the shell.",
                },
                {
                    "what": "Confirm: the substituted output appears in the response, usually inside a ping error "
                            "like 'cannot resolve uid=0(root): Name or service not known'.",
                    "how":  "Read the response for your command's output embedded in the ping/resolve error.",
                    "look_for": "A 'Command injection confirmed' card.",
                },
            ],
        },
    },

    # ─── DIR TRAVERSAL ──────────────────────────────────────────────────
    "dir_traversal": {
        "plain": {
            "overview": (
                "Path traversal (a.k.a. directory traversal) abuses a file-reading feature that "
                "builds a path from user input. By inserting '../' sequences you climb OUT of the "
                "intended folder and read arbitrary files on the server — like /etc/passwd. The "
                "/files/read page is meant to serve docs from one directory; this breaks out of it."
            ),
            "sections": [
                {
                    "what": "See the feature working as intended first: it reads a file by name from a fixed folder.",
                    "how":  "Open /files/read?path=readme.txt and read the file's contents in the lab browser.",
                    "look_for": "A 'File viewer used' card — the reader accepts a path parameter.",
                },
                {
                    "what": "Each '../' moves up one directory. String enough together and you escape the web "
                            "root entirely into the OS filesystem.",
                    "how":  "Change the path to climb out: path=../../etc/passwd (add more ../ if needed to reach root).",
                    "look_for": "A 'Path traversal observed' card — a traversal sequence was detected.",
                },
                {
                    "what": "Proof: the server returns the contents of a sensitive system file it should never expose.",
                    "how":  "Confirm the response contains lines like 'root:x:0:0:' from /etc/passwd.",
                    "look_for": "A 'Sensitive file disclosed' card — you read a protected file.",
                },
            ],
        },
        "encoded": {
            "overview": (
                "When a filter strips literal '../', you encode it. %2e is '.', %2f is '/', so "
                "%2e%2e%2f is '../' after the server URL-decodes it. Double-encoding (%252e) beats "
                "filters that decode only once. The lesson: blocking a string is not the same as "
                "understanding the path."
            ),
            "sections": [
                {
                    "what": "Confirm the reader works so later failures point at the filter, not the endpoint.",
                    "how":  "Open /files/read?path=readme.txt.",
                    "look_for": "A 'File viewer used' card.",
                },
                {
                    "what": "Send the traversal URL-encoded so the filter's literal '../' check never matches, but "
                            "the server still decodes it back to '../' before opening the file.",
                    "how":  "Try two encodings: path=..%2F..%2Fetc%2Fpasswd  and double-encoded "
                            "path=%252e%252e%252fetc%252fpasswd.",
                    "look_for": "A 'Path traversal observed' card — an encoded sequence got through.",
                },
                {
                    "what": "Proof: the decoded path escaped the folder and disclosed a system file.",
                    "how":  "Confirm /etc/passwd content ('root:x:0:0:') appears in the response.",
                    "look_for": "A 'Sensitive file disclosed' card.",
                },
            ],
        },
        "absolute": {
            "overview": (
                "Sometimes you don't need '../' at all. If the app naively concatenates or trusts the "
                "path, handing it an ABSOLUTE path like /etc/passwd skips the traversal entirely. This "
                "catches apps that carefully strip '../' but forget that '/etc/passwd' is already a full path."
            ),
            "sections": [
                {
                    "what": "Establish the baseline read behaviour.",
                    "how":  "Open /files/read?path=readme.txt.",
                    "look_for": "A 'File viewer used' card.",
                },
                {
                    "what": "Skip the dot-dot dance. Provide a full absolute path and see if the reader opens it "
                            "directly — many ../-stripping filters miss this.",
                    "how":  "Set path=/etc/passwd (no ../ at all). Also try path=/etc/hostname.",
                    "look_for": "A 'Path traversal observed' card — the absolute path was accepted.",
                },
                {
                    "what": "Proof: a sensitive file is disclosed via the absolute path.",
                    "how":  "Confirm 'root:x:0:0:' (passwd) or the machine hostname appears in the response.",
                    "look_for": "A 'Sensitive file disclosed' card.",
                },
            ],
        },
    },

    # ─── FILE UPLOAD ────────────────────────────────────────────────────
    "file_upload": {
        "wrong_extension": {
            "overview": (
                "Unrestricted file upload lets an attacker put their OWN file on the server. The most "
                "basic test is the extension check: if the app accepts a .php or .sh file, an attacker "
                "can upload a web shell and later browse to it to run commands. Here you confirm the "
                "uploader doesn't validate what kind of file it stores."
            ),
            "sections": [
                {
                    "what": "Confirm the upload works at all with a harmless file, and note where it gets stored.",
                    "how":  "Upload a small probe.txt via /files/upload (drag-drop in the browser or "
                            "curl -F 'file=@probe.txt' http://target-agent/files/upload).",
                    "look_for": "An 'Upload form used' and 'File saved' card — the file landed on the server.",
                },
                {
                    "what": "Now try a dangerous executable extension. A .php file that the web server would "
                            "execute is the classic web-shell vector.",
                    "how":  "Upload shell.php (contents like <?php echo 'x'; ?>). curl -F 'file=@shell.php' "
                            "http://target-agent/files/upload.",
                    "look_for": "A 'Dangerous extension accepted' card — the server stored a .php file.",
                },
                {
                    "what": "Proof: the server returns a stored path with no validation — an attacker now has a "
                            "file they control inside the app.",
                    "how":  "Confirm the response gives a path under /static/uploads/ for your dangerous file.",
                    "look_for": "An 'Unrestricted upload confirmed' card.",
                },
            ],
        },
        "mime_spoof": {
            "overview": (
                "Smarter uploaders check the Content-Type header to decide if a file is 'an image'. But "
                "the client sets that header — so you can lie. Send your .php while claiming "
                "Content-Type: image/png and a trusting server stores it as if it were a harmless image."
            ),
            "sections": [
                {
                    "what": "Confirm a genuine image uploads cleanly, establishing what a 'valid' upload looks like.",
                    "how":  "Upload any real .png/.jpg via /files/upload.",
                    "look_for": "A 'File saved' card.",
                },
                {
                    "what": "Now spoof the type: send a PHP payload but tag it Content-Type: image/png so a "
                            "header-only check is fooled.",
                    "how":  "curl -F 'file=@shell.php;type=image/png' http://target-agent/files/upload.",
                    "look_for": "A 'Dangerous extension accepted' card — the spoofed MIME slipped through.",
                },
                {
                    "what": "Proof: the executable file was stored despite the fake type — MIME was never truly enforced.",
                    "how":  "Confirm the response returns a stored path for your disguised .php.",
                    "look_for": "An 'Unrestricted upload confirmed' card.",
                },
            ],
        },
        "polyglot": {
            "overview": (
                "A polyglot file is valid as TWO formats at once: it begins with real image magic bytes "
                "(so content-sniffing sees a JPEG) yet also contains a working script payload. This "
                "defeats servers that check BOTH the file's real bytes AND its extension — the file "
                "honestly is an image, and also a shell."
            ),
            "sections": [
                {
                    "what": "Confirm the endpoint accepts uploads before crafting the tricky file.",
                    "how":  "Upload any baseline file via /files/upload.",
                    "look_for": "A 'File saved' card.",
                },
                {
                    "what": "Build a polyglot: prepend JPEG magic bytes (\\xff\\xd8\\xff\\xe0) to a PHP payload and "
                            "save it as poly.jpg.php — it sniffs as an image but runs as PHP.",
                    "how":  "printf '\\xff\\xd8\\xff\\xe0' > poly.jpg.php; echo '<?php system($_GET[\"c\"]); ?>' "
                            ">> poly.jpg.php; curl -F 'file=@poly.jpg.php;type=image/jpeg' http://target-agent/files/upload.",
                    "look_for": "A 'Dangerous extension accepted' card — both checks were beaten.",
                },
                {
                    "what": "Proof: the polyglot was stored — content sniffing AND extension filtering both failed.",
                    "how":  "Confirm the response returns a stored path for the polyglot.",
                    "look_for": "An 'Unrestricted upload confirmed' card.",
                },
            ],
        },
    },

    # ─── CSRF ───────────────────────────────────────────────────────────
    "csrf": {
        "basic_forgery": {
            "overview": (
                "Cross-Site Request Forgery abuses the fact that browsers auto-send your cookies with "
                "every request. If a state-changing form (like 'update profile') has no anti-CSRF token, "
                "any page can submit it on your behalf using your logged-in session. Here you prove the "
                "profile update accepts a forged POST with no token."
            ),
            "sections": [
                {
                    "what": "CSRF rides an authenticated session, so first log in and hold the session cookie.",
                    "how":  "Log in as admin:password123. From a terminal: "
                            "curl -c /tmp/c.txt -d 'username=admin&password=password123' http://target-agent/auth/login.",
                    "look_for": "A 'Successful login observed' card.",
                },
                {
                    "what": "Submit the state-changing request WITHOUT any CSRF token — exactly what an attacker's "
                            "page would do with your cookie.",
                    "how":  "curl -b /tmp/c.txt -d 'email=pwned@evil.lab' http://target-agent/profile/update.",
                    "look_for": "A 'Profile update without a CSRF token' card — the server accepted a tokenless change.",
                },
                {
                    "what": "Proof: the change actually persisted, confirming the forgery worked end-to-end.",
                    "how":  "Re-read the profile: curl -b /tmp/c.txt http://target-agent/profile/ and confirm "
                            "the email is now pwned@evil.lab.",
                    "look_for": "A 'Profile changed without CSRF protection' card.",
                },
            ],
        },
        "lure_page": {
            "overview": (
                "This is CSRF as it happens in the wild. The lab ships an attacker page, /evil/csrf-demo, "
                "that auto-submits a forged profile update the moment a logged-in victim opens it. The "
                "victim never clicks anything malicious — just visiting the page (while logged in elsewhere) "
                "is enough to change their account."
            ),
            "sections": [
                {
                    "what": "Set up the victim: an authenticated session is the precondition for the lure to work.",
                    "how":  "Log in as admin in the lab browser so you hold a live session.",
                    "look_for": "A 'Successful login observed' card.",
                },
                {
                    "what": "Open the attacker-controlled page. It contains a hidden form targeting /profile/update "
                            "that fires automatically — simulating a malicious site you stumbled onto.",
                    "how":  "Navigate to /evil/csrf-demo in the lab browser while still logged in.",
                    "look_for": "An 'Attacker lure page visited' card.",
                },
                {
                    "what": "Proof: the lure's auto-submitted request changed your profile silently, using your cookie.",
                    "how":  "The page auto-submits; then re-open /profile/ and confirm the email changed.",
                    "look_for": "A 'Forged form submitted' and 'Profile changed without CSRF protection' card.",
                },
            ],
        },
        "json_bypass": {
            "overview": (
                "Some apps add CSRF defences only to form-encoded POSTs and forget about JSON. By sending "
                "the same state-changing request with Content-Type: application/json, you can slip past a "
                "filter that only inspects classic form submissions — a subtle but common real-world gap."
            ),
            "sections": [
                {
                    "what": "Authenticate to get a session, as with any CSRF test.",
                    "how":  "Log in as admin:password123 and keep the cookie (curl -c /tmp/c.txt ...).",
                    "look_for": "A 'Successful login observed' card.",
                },
                {
                    "what": "Re-send the profile update as JSON instead of form data. Filters that only guard "
                            "application/x-www-form-urlencoded won't inspect this.",
                    "how":  "curl -b /tmp/c.txt -H 'Content-Type: application/json' "
                            "-d '{\"email\":\"pwned@evil.lab\"}' http://target-agent/profile/update.",
                    "look_for": "A 'Profile update used' card — the JSON body was accepted.",
                },
                {
                    "what": "Proof: the change persisted, confirming the JSON path bypassed CSRF protection.",
                    "how":  "Re-read the profile and confirm the email is now pwned@evil.lab.",
                    "look_for": "A 'Profile changed without CSRF protection' card.",
                },
            ],
        },
    },

    # ─── RECON ──────────────────────────────────────────────────────────
    "recon": {
        "manual": {
            "overview": (
                "Reconnaissance is mapping the target before you attack. Manual recon means walking the "
                "app like a curious user — clicking every link, reading every page — to build a mental "
                "map of the features and where they might be weak. It's slow but stealthy and teaches you "
                "the app's real shape."
            ),
            "sections": [
                {
                    "what": "Start at the front door. The home page usually links to most of the app's features.",
                    "how":  "Open / in the lab browser and read what's there.",
                    "look_for": "A 'Portal visited' card.",
                },
                {
                    "what": "Visit the distinct areas the app exposes — search, profile, file viewer, diagnostics. "
                            "Each is a candidate attack surface for a later module.",
                    "how":  "Click through to at least 3 areas: /search, /profile/, /files/read, /system/ping.",
                    "look_for": "Several 'Route discovered' / feature-used cards (3+ areas marks this done).",
                },
                {
                    "what": "Visiting enough distinct areas in sequence trips the lab's recon-sequence detector — "
                            "the blue-team signature of someone mapping the app.",
                    "how":  "Keep exploring until you've hit 4+ distinct areas.",
                    "look_for": "A 'Recon sequence detected' card.",
                },
            ],
        },
        "wordlist": {
            "overview": (
                "Wordlist (or content) discovery finds routes that aren't linked anywhere on the site. "
                "Tools like gobuster/ffuf hammer the server with a list of common paths and keep the ones "
                "that return something — uncovering hidden admin panels, demos, and forgotten endpoints "
                "the developers never advertised."
            ),
            "sections": [
                {
                    "what": "Confirm the target is up and how it responds to a known-good path, so you can tell hits "
                            "from misses during the scan.",
                    "how":  "curl -i http://target-agent/ and note the response.",
                    "look_for": "A 'Portal visited' card.",
                },
                {
                    "what": "Brute-force paths with a wordlist. Every 200/301/302 is a real route the home page "
                            "may not link to.",
                    "how":  "gobuster dir -u http://target-agent -w /usr/share/wordlists/dirb/common.txt -t 20 "
                            "(or loop curl over a path list), then visit each hit.",
                    "look_for": "Multiple 'Route discovered' cards (4+ endpoints marks this done).",
                },
                {
                    "what": "The payoff of fuzzing is the hidden stuff — a route or clue not reachable by clicking, "
                            "like /evil/csrf-demo or /robots.txt.",
                    "how":  "Request the non-obvious paths your wordlist surfaced and read them.",
                    "look_for": "A 'Hidden clue accessed' (or lure-visited) card.",
                },
            ],
        },
        "comment_hunting": {
            "overview": (
                "Developers leak secrets in plain sight: HTML comments, version banners, and debug notes "
                "left in the page source. Comment hunting means reading the raw HTML/JS — not the rendered "
                "page — for these mistakes. A single '<!-- TODO: remove admin login /secret-admin -->' can "
                "hand you the whole app."
            ),
            "sections": [
                {
                    "what": "Grab the raw source of the home page — comments and banners live in the HTML, not the "
                            "visible page.",
                    "how":  "curl -s http://target-agent/ and read the full markup.",
                    "look_for": "A 'Portal visited' card.",
                },
                {
                    "what": "Grep the source for tell-tale leaks: HTML comments, 'Server'/'version' strings, "
                            "framework banners. These reveal stack details and sometimes hidden URLs.",
                    "how":  "curl -s http://target-agent/ | grep -iE '<!--|server|version|powered' and inspect "
                            "headers with curl -sI.",
                    "look_for": "Several 'Route discovered' / feature cards as you follow the leads.",
                },
                {
                    "what": "Comments often point at something hidden — an admin path, a demo page, a backup. "
                            "Following the leak uncovers a non-obvious route.",
                    "how":  "Visit whatever URL or hint the comments disclosed.",
                    "look_for": "A 'Hidden clue accessed' card.",
                },
            ],
        },
    },
}


def get_walkthrough(module_id: str, variant_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the walkthrough entry for (module, variant), defaulting to the
    first variant when none is supplied. None when no teaching content exists."""
    mod = WALKTHROUGH.get(module_id)
    if not mod:
        return None
    if not variant_id:
        variant_id = next(iter(MODULE_VARIANTS.get(module_id, {})), None)
    return mod.get(variant_id)


# ═══════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK — one technique per walkthrough section (aligned by index).
#  Format: "Txxxx[.yyy] · Short technique name". The frontend turns the id
#  into a clickable attack.mitre.org link so each section is grounded in the
#  authoritative ATT&CK knowledge base.
# ═══════════════════════════════════════════════════════════════════════════
SECTION_TECHNIQUES: Dict[str, Dict[str, List[str]]] = {
    "brute_force": {
        "password_spray": [
            "T1589.001 · Gather Victim Identity Information: Credentials",
            "T1087 · Account Discovery",
            "T1110.003 · Brute Force: Password Spraying",
            "T1078 · Valid Accounts",
        ],
        "credential_stuffing": [
            "T1595 · Active Scanning",
            "T1110.004 · Brute Force: Credential Stuffing",
            "T1110 · Brute Force",
            "T1078 · Valid Accounts",
        ],
        "hydra_targeted": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1110.001 · Brute Force: Password Guessing",
            "T1110 · Brute Force",
            "T1078 · Valid Accounts",
        ],
    },
    "xss": {
        "reflected": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1059.007 · Command and Scripting Interpreter: JavaScript",
            "T1189 · Drive-by Compromise",
        ],
        "alternate_context": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1059.007 · Command and Scripting Interpreter: JavaScript",
            "T1059.007 · Command and Scripting Interpreter: JavaScript",
        ],
        "stored_attempt": [
            "T1078 · Valid Accounts",
            "T1059.007 · Command and Scripting Interpreter: JavaScript",
            "T1189 · Drive-by Compromise",
        ],
    },
    "cmd_injection": {
        "semicolon_basic": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1059 · Command and Scripting Interpreter",
            "T1059.004 · Command and Scripting Interpreter: Unix Shell",
        ],
        "pipe_redirect": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1059 · Command and Scripting Interpreter",
            "T1059.004 · Command and Scripting Interpreter: Unix Shell",
        ],
        "subshell": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1059 · Command and Scripting Interpreter",
            "T1059.004 · Command and Scripting Interpreter: Unix Shell",
        ],
    },
    "dir_traversal": {
        "plain": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1083 · File and Directory Discovery",
            "T1005 · Data from Local System",
        ],
        "encoded": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1027 · Obfuscated Files or Information",
            "T1005 · Data from Local System",
        ],
        "absolute": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1083 · File and Directory Discovery",
            "T1005 · Data from Local System",
        ],
    },
    "file_upload": {
        "wrong_extension": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1505.003 · Server Software Component: Web Shell",
            "T1190 · Exploit Public-Facing Application",
        ],
        "mime_spoof": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1036 · Masquerading",
            "T1505.003 · Server Software Component: Web Shell",
        ],
        "polyglot": [
            "T1595.002 · Active Scanning: Vulnerability Scanning",
            "T1027 · Obfuscated Files or Information",
            "T1505.003 · Server Software Component: Web Shell",
        ],
    },
    "csrf": {
        "basic_forgery": [
            "T1539 · Steal Web Session Cookie",
            "T1190 · Exploit Public-Facing Application",
            "T1565.001 · Data Manipulation: Stored Data Manipulation",
        ],
        "lure_page": [
            "T1078 · Valid Accounts",
            "T1189 · Drive-by Compromise",
            "T1565.001 · Data Manipulation: Stored Data Manipulation",
        ],
        "json_bypass": [
            "T1078 · Valid Accounts",
            "T1190 · Exploit Public-Facing Application",
            "T1565.001 · Data Manipulation: Stored Data Manipulation",
        ],
    },
    "recon": {
        "manual": [
            "T1594 · Search Victim-Owned Websites",
            "T1592 · Gather Victim Host Information",
            "T1595.002 · Active Scanning: Vulnerability Scanning",
        ],
        "wordlist": [
            "T1595 · Active Scanning",
            "T1595.003 · Active Scanning: Wordlist Scanning",
            "T1083 · File and Directory Discovery",
        ],
        "comment_hunting": [
            "T1594 · Search Victim-Owned Websites",
            "T1592.002 · Gather Victim Host Information: Software",
            "T1213 · Data from Information Repositories",
        ],
    },
}


# ── Authoritative references per module (OWASP / online databases) ──────────
REFERENCES: Dict[str, Dict[str, str]] = {
    "brute_force":   {"label": "OWASP: Brute Force Attack",        "url": "https://owasp.org/www-community/attacks/Brute_force_attack"},
    "xss":           {"label": "OWASP: Cross Site Scripting (XSS)", "url": "https://owasp.org/www-community/attacks/xss/"},
    "cmd_injection": {"label": "OWASP: Command Injection",          "url": "https://owasp.org/www-community/attacks/Command_Injection"},
    "dir_traversal": {"label": "OWASP: Path Traversal",            "url": "https://owasp.org/www-community/attacks/Path_Traversal"},
    "file_upload":   {"label": "OWASP: Unrestricted File Upload",  "url": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"},
    "csrf":          {"label": "OWASP: Cross-Site Request Forgery", "url": "https://owasp.org/www-community/attacks/csrf"},
    "recon":         {"label": "OWASP WSTG: Information Gathering", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
}

DATABASE_REFERENCES: Dict[str, List[Dict[str, str]]] = {
    "brute_force": [
        {"label": "OWASP Brute Force", "url": "https://owasp.org/www-community/attacks/Brute_force_attack", "kind": "OWASP"},
        {"label": "CWE-307 Excessive Authentication Attempts", "url": "https://cwe.mitre.org/data/definitions/307.html", "kind": "CWE"},
        {"label": "CWE-287 Improper Authentication", "url": "https://cwe.mitre.org/data/definitions/287.html", "kind": "CWE"},
    ],
    "xss": [
        {"label": "OWASP Cross Site Scripting", "url": "https://owasp.org/www-community/attacks/xss/", "kind": "OWASP"},
        {"label": "CWE-79 Cross-site Scripting", "url": "https://cwe.mitre.org/data/definitions/79.html", "kind": "CWE"},
        {"label": "OWASP WSTG Client-side Testing", "url": "https://owasp.org/www-project-web-security-testing-guide/", "kind": "WSTG"},
    ],
    "cmd_injection": [
        {"label": "OWASP Command Injection", "url": "https://owasp.org/www-community/attacks/Command_Injection", "kind": "OWASP"},
        {"label": "CWE-78 OS Command Injection", "url": "https://cwe.mitre.org/data/definitions/78.html", "kind": "CWE"},
        {"label": "CAPEC-248 Command Injection", "url": "https://capec.mitre.org/data/definitions/248.html", "kind": "CAPEC"},
    ],
    "dir_traversal": [
        {"label": "OWASP Path Traversal", "url": "https://owasp.org/www-community/attacks/Path_Traversal", "kind": "OWASP"},
        {"label": "CWE-22 Path Traversal", "url": "https://cwe.mitre.org/data/definitions/22.html", "kind": "CWE"},
        {"label": "CAPEC-126 Path Traversal", "url": "https://capec.mitre.org/data/definitions/126.html", "kind": "CAPEC"},
    ],
    "file_upload": [
        {"label": "OWASP Unrestricted File Upload", "url": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", "kind": "OWASP"},
        {"label": "CWE-434 Unrestricted Upload", "url": "https://cwe.mitre.org/data/definitions/434.html", "kind": "CWE"},
        {"label": "CAPEC-650 Upload a Web Shell", "url": "https://capec.mitre.org/data/definitions/650.html", "kind": "CAPEC"},
    ],
    "csrf": [
        {"label": "OWASP CSRF", "url": "https://owasp.org/www-community/attacks/csrf", "kind": "OWASP"},
        {"label": "CWE-352 Cross-Site Request Forgery", "url": "https://cwe.mitre.org/data/definitions/352.html", "kind": "CWE"},
        {"label": "OWASP CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html", "kind": "Cheat Sheet"},
    ],
    "recon": [
        {"label": "OWASP WSTG Information Gathering", "url": "https://owasp.org/www-project-web-security-testing-guide/", "kind": "WSTG"},
        {"label": "CWE-200 Exposure of Sensitive Information", "url": "https://cwe.mitre.org/data/definitions/200.html", "kind": "CWE"},
        {"label": "ATT&CK Reconnaissance", "url": "https://attack.mitre.org/tactics/TA0043/", "kind": "MITRE"},
    ],
}

MODULE_SECTION_PHASES: Dict[str, List[str]] = {
    "recon": ["Reconnaissance", "Discovery", "Discovery"],
    "brute_force": ["Credential access", "Account discovery", "Detection signal", "Valid accounts"],
    "xss": ["Input discovery", "Payload delivery", "Execution"],
    "cmd_injection": ["Input discovery", "Command execution", "Impact proof"],
    "dir_traversal": ["Input discovery", "File discovery", "Collection"],
    "file_upload": ["Upload baseline", "Payload delivery", "Public exposure"],
    "csrf": ["Session setup", "Request forgery", "Stored data manipulation"],
}


def _section_phase(module_id: str, index: int) -> str:
    phases = MODULE_SECTION_PHASES.get(module_id) or []
    if not phases:
        return "Attack path"
    return phases[index] if index < len(phases) else phases[-1]


def build_walkthrough(module_id: str, variant_id: Optional[str] = None) -> Dict[str, Any]:
    """Assemble the full guided-room payload for a (module, variant) WITHOUT
    needing a started session. Consumed by GET /api/modules/{id}/walkthrough
    and rendered as the TryHackMe-style guided room."""
    variants = MODULE_VARIANTS.get(module_id, {})
    if not variant_id or variant_id not in variants:
        variant_id = next(iter(variants), None)
    variant = variants.get(variant_id) or {}
    wt = (WALKTHROUGH.get(module_id, {}) or {}).get(variant_id) or {}
    tasks = variant.get("tasks", [])
    techs = (SECTION_TECHNIQUES.get(module_id, {}) or {}).get(variant_id, [])
    secs  = wt.get("sections", [])
    database_refs = DATABASE_REFERENCES.get(module_id, [])

    sections: List[Dict[str, Any]] = []
    for i in range(max(len(tasks), len(secs))):
        sec = secs[i] if i < len(secs) else {}
        t   = tasks[i] if i < len(tasks) else {}
        sections.append({
            "title":    t.get("title") or f"Step {i + 1}",
            "phase":    sec.get("phase") or _section_phase(module_id, i),
            "what":     sec.get("what"),
            "how":      sec.get("how") or t.get("explain"),
            "look_for": sec.get("look_for"),
            "checkpoint": t.get("explain"),
            "mitre":    techs[i] if i < len(techs) else None,
            "database_refs": database_refs,
        })

    spec = PROGRESS_SPECS.get(module_id, {})
    return {
        "module_id":         module_id,
        "variant_id":        variant_id,
        "variant_name":      variant.get("name"),
        "variant_description": variant.get("description"),
        "difficulty":        variant.get("difficulty"),
        "techniques":        variant.get("techniques", []),
        "overview":          wt.get("overview"),
        "defensive_insight": spec.get("defensive_insight"),
        "reference":         REFERENCES.get(module_id),
        "database_refs":     database_refs,
        "sections":          sections,
    }


def get_variant_spec(module_id: str, variant_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the variant entry for (module, variant) or None if unknown."""
    variants = MODULE_VARIANTS.get(module_id)
    if not variants:
        return None
    if not variant_id:
        # First variant is the default
        variant_id = next(iter(variants))
    return variants.get(variant_id)


def list_variants(module_id: str) -> List[Dict[str, Any]]:
    """Return a list of (id + metadata) for the module's variants — used by the UI picker."""
    variants = MODULE_VARIANTS.get(module_id, {})
    return [
        {
            "variant_id":  vid,
            "name":        v["name"],
            "description": v["description"],
            "difficulty":  v.get("difficulty", "Medium"),
            "techniques":  v.get("techniques", []),
        }
        for vid, v in variants.items()
    ]


# ═══════════════════════════════════════════════════════════════════════════
#  OBJECTIVE-BASED PROGRESS MODEL
#
#  Mission COMPLETION is objective-based: it depends on reaching the real attack
#  target, NOT on finishing a fixed checklist in order. Learning QUALITY (did the
#  student follow good methodology?) is scored separately and NEVER blocks
#  completion. Safety is confirmed by the existing operator gating and surfaced
#  as non-blocking warnings.
#
#  Each module declares:
#    objective          — one-line student-facing goal (no solution leak)
#    completion_groups  — list of OR-groups. A group is satisfied when ANY of its
#                         event types is observed *through the gated channel*
#                         (operator route + backend=operator + approved tool in
#                         lab mode). ALL groups must be satisfied → objective
#                         reached. One correct action can satisfy several groups.
#    quality_tasks      — recommended methodology signals used for scoring and
#                         report coaching. Each: id, label, recommendation, and a
#                         matcher (event_types and/or via). Matched only against
#                         high-quality local-tool evidence so browser proof can
#                         complete objectives without inflating methodology.
#
#  brute_force keeps its dedicated failure-count completion; its quality tasks
#  are scored the same way as every other module.
# ═══════════════════════════════════════════════════════════════════════════
_CAP_VIA = ["browser", "zap_repeater", "zap_fuzzer"]   # request visible in ZAP history

OBJECTIVE_SPECS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "objective": "Discover and verify a hidden local route on the operator portal.",
        "completion_groups": [["hidden_clue_accessed", "recon_sequence_observed"]],
        "quality_tasks": [
            {"id": "portal_mapped", "label": "Map the portal home first",
             "event_types": ["portal_visited"],
             "recommendation": "Start by visiting /op/ and mapping the visible routes."},
            {"id": "discovery_files_checked", "label": "Check common discovery files",
             "event_types": ["route_discovered"],
             "recommendation": "Request /op/robots.txt and /op/.well-known/security.txt and read the responses."},
            {"id": "verified_with_tool", "label": "Verify a route with Repeater or AttackBox",
             "via": ["zap_repeater", "attackbox"],
             "recommendation": "Confirm an interesting path with ZAP Repeater or a safe AttackBox curl before trusting it."},
        ],
    },
    "xss": {
        "objective": "Trigger a safe reflected XSS proof on /op/search.",
        "completion_groups": [
            ["xss_payload_observed"],
            ["reflected_input_detected", "stored_payload_observed"],
        ],
        "quality_tasks": [
            {"id": "request_captured", "label": "Capture the request in ZAP", "via": _CAP_VIA,
             "recommendation": "Submit a query and capture the /op/search request in ZAP Proxy History."},
            {"id": "context_inspected", "label": "Inspect the reflection context",
             "event_types": ["xss_context_identified"],
             "recommendation": "Use the Inspector to find where your input is reflected before choosing a payload."},
            {"id": "repeater_used", "label": "Test through Repeater", "via": ["zap_repeater"],
             "recommendation": "Send the request to Repeater and change one thing at a time."},
            {"id": "marker_first", "label": "Test a harmless marker first",
             "event_types": ["xss_marker_tested"],
             "recommendation": "Test a benign marker (e.g. ATTENSE_XSS_PROOF) before a live payload."},
            {"id": "fuzzer_used", "label": "Iterate payloads with the Fuzzer", "via": ["zap_fuzzer"],
             "recommendation": "Use the Fuzzer to iterate payload variants against the input parameter."},
        ],
    },
    "cmd_injection": {
        "objective": "Prove OS command execution on /op/system/ping with a harmless command.",
        "completion_groups": [["command_injection_detected"]],
        "quality_tasks": [
            {"id": "request_captured", "label": "Capture the request in ZAP", "via": _CAP_VIA,
             "recommendation": "Capture the /op/system/ping request in ZAP Proxy History."},
            {"id": "baseline_first", "label": "Establish a clean baseline",
             "event_types": ["diagnostics_used"],
             "recommendation": "Send a normal host value first so you can tell injected output from normal output."},
            {"id": "repeater_used", "label": "Test through Repeater", "via": ["zap_repeater"],
             "recommendation": "Use Repeater and modify one parameter at a time."},
            {"id": "separator_tested", "label": "Test a shell separator",
             "event_types": ["command_separator_observed"],
             "recommendation": "Add one separator at a time and compare responses."},
            {"id": "fuzzer_used", "label": "Iterate separators with the Fuzzer", "via": ["zap_fuzzer"],
             "recommendation": "Use the Fuzzer to test separators when unsure which one works."},
        ],
    },
    "dir_traversal": {
        "objective": "Disclose a sensitive lab file via the /op/files/read parameter.",
        "completion_groups": [
            ["sensitive_file_disclosed", "lab_file_disclosed"],
            ["traversal_pattern_observed"],
        ],
        "quality_tasks": [
            {"id": "request_captured", "label": "Capture the request in ZAP", "via": _CAP_VIA,
             "recommendation": "Capture the /op/files/read request in ZAP Proxy History."},
            {"id": "baseline_first", "label": "Request a normal file first",
             "event_types": ["file_viewer_used"],
             "recommendation": "Read a normal filename first as your baseline."},
            {"id": "repeater_used", "label": "Test through Repeater", "via": ["zap_repeater"],
             "recommendation": "Use Repeater and modify only the filename parameter."},
            {"id": "encoded_variant", "label": "Try an encoded variant if filtered",
             "event_types": ["traversal_encoded_tested"],
             "recommendation": "If plain sequences are filtered, test encoded variants."},
        ],
    },
    "file_upload": {
        "objective": "Get a dangerous file accepted by /op/files/upload.",
        "completion_groups": [
            ["unrestricted_upload_detected", "dangerous_extension_accepted", "uploaded_file_retrieved"],
        ],
        "quality_tasks": [
            {"id": "multipart_captured", "label": "Capture the multipart request",
             "event_types": ["file_upload_used"],
             "recommendation": "Capture the multipart /op/files/upload request and inspect its fields."},
            {"id": "request_captured", "label": "Inspect the request in ZAP", "via": _CAP_VIA,
             "recommendation": "Inspect the filename field and the file part Content-Type in ZAP."},
            {"id": "repeater_used", "label": "Test through Repeater", "via": ["zap_repeater"],
             "recommendation": "Use Repeater and change one validation field at a time (extension or Content-Type)."},
            {"id": "retrieved_proof", "label": "Retrieve the uploaded proof file",
             "event_types": ["uploaded_file_retrieved"],
             "recommendation": "Retrieve the uploaded proof file to confirm it is served (use a harmless file only)."},
        ],
    },
    "csrf": {
        "objective": "Change the profile via /op/profile/update without a CSRF token.",
        "completion_groups": [["profile_changed_without_csrf"]],
        "quality_tasks": [
            {"id": "request_captured", "label": "Capture the state-changing request", "via": _CAP_VIA,
             "recommendation": "Capture the /op/profile/update request in ZAP Proxy History."},
            {"id": "token_absence_identified", "label": "Identify the missing CSRF token",
             "event_types": ["csrf_token_missing"],
             "recommendation": "Confirm the state-changing request carries no CSRF token."},
            {"id": "repeater_used", "label": "Confirm the change through Repeater", "via": ["zap_repeater"],
             "recommendation": "Replay the request from Repeater without a token to confirm it still works."},
            {"id": "lure_used", "label": "Use the local lure page",
             "event_types": ["csrf_lure_visited", "csrf_lure_submitted"],
             "recommendation": "Use the local /op/evil/csrf-demo lure to recreate the cross-site submission."},
        ],
    },
    "brute_force": {
        "objective": (
            "Discover a valid credential on /op/auth/login (6+ failed attempts, "
            "detector triggered), then confirm the valid login on the operator "
            "surface. Repeater confirmation improves methodology quality."
        ),
        # Completion is computed by the dedicated brute_force_activity logic, not
        # these groups; they are kept for documentation/report labelling.
        "completion_groups": [["brute_force_pattern"], ["credential_found", "login_success"]],
        "quality_tasks": [
            {"id": "request_captured", "label": "Capture the login request", "via": _CAP_VIA,
             "recommendation": "Capture the POST /op/auth/login request in ZAP Proxy History."},
            {"id": "repeater_used", "label": "Understand the request in Repeater", "via": ["zap_repeater"],
             "recommendation": "Send the request to Repeater to learn its format before automating."},
            {"id": "fuzzer_used", "label": "Automate with the Fuzzer", "via": ["zap_fuzzer"],
             "recommendation": "Use the Fuzzer with the local wordlist and compare status/length between attempts."},
            {"id": "credential_confirmed", "label": "Confirm the credential by hand in Repeater",
             "event_types": ["credential_found", "login_success"], "via": ["zap_repeater"],
             "recommendation": (
                 "Send the discovered username and password through ZAP Repeater "
                 "yourself and compare the 302/profile redirect against failed attempts."
             )},
        ],
    },
}


# Explicit operator surfaces per module (the /op/ paths that can carry
# completion/quality evidence). Used to enrich each spec with the operator-
# contract metadata the API and docs reference.
_MODULE_OP_PATHS: Dict[str, List[str]] = {
    "recon":         ["/op/", "/op/.git/config"],
    "xss":           ["/op/search"],
    "cmd_injection": ["/op/system/ping"],
    "dir_traversal": ["/op/files/read"],
    "file_upload":   ["/op/files/upload"],
    "csrf":          ["/op/profile/update", "/op/evil/csrf-demo", "/op/profile/"],
    "brute_force":   ["/op/auth/login"],
}

# Normalize each spec with the explicit operator-contract metadata, derived from
# the working structures above so there is a single source of truth. This gives
# every module: objective, required_completion, quality_events,
# expected_operator_paths, expected_backend, allowed_operator_via,
# next_recommended_action.
for _mid, _spec in OBJECTIVE_SPECS.items():
    _spec.setdefault("required_completion", _spec.get("completion_groups", []))
    _spec.setdefault("quality_events", [qt["id"] for qt in _spec.get("quality_tasks", [])])
    _spec.setdefault("expected_operator_paths", _MODULE_OP_PATHS.get(_mid, ["/op/"]))
    _spec.setdefault("expected_backend", "operator")
    _spec.setdefault("allowed_operator_via", sorted(_allowed_via_for(_mid)))
    _spec.setdefault(
        "next_recommended_action",
        (_spec.get("quality_tasks") or [{}])[0].get("recommendation"),
    )


def get_objective_spec(module_id: str) -> Dict[str, Any]:
    """Return the objective spec for a module (empty dict if none)."""
    return OBJECTIVE_SPECS.get(module_id, {})


def completion_event_types(module_id: str) -> List[str]:
    """One representative goal event that completes the mission. Used by tests
    and callers that need to synthesise a 'just completed' evidence set. Under
    the goal-trigger model a single goal event is enough, so this returns one
    representative goal type."""
    goals = sorted(GOAL_TRIGGERS.get(module_id, set()))
    return goals[:1]


def _quality_task_matched(qt: Dict[str, Any], module_events: List[Dict[str, Any]]) -> bool:
    ets = set(qt.get("event_types", []))
    vias = set(qt.get("via", []))
    for e in module_events:
        if ets and vias:
            if e.get("event_type") in ets and str(e.get("via") or "") in vias:
                return True
            continue
        if ets and e.get("event_type") in ets:
            return True
        if vias and str(e.get("via") or "") in vias:
            return True
    return False


def _quality_report(module_id: str,
                    module_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Score recommended methodology. NEVER affects completion."""
    tasks = OBJECTIVE_SPECS.get(module_id, {}).get("quality_tasks", [])
    completed: List[Dict[str, str]] = []
    missing: List[Dict[str, str]] = []
    for qt in tasks:
        entry = {"id": qt["id"], "label": qt["label"],
                 "recommendation": qt.get("recommendation", "")}
        (completed if _quality_task_matched(qt, module_events) else missing).append(entry)
    total = len(tasks)
    score = int(round(100 * len(completed) / total)) if total else 0
    return {"completed": completed, "missing": missing, "score": score, "total": total}


def _completion_report(module_id: str,
                       gated_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Objective-based completion from gated events. Returns reached flag,
    a 0-100 completion score (proportional across groups), and human labels for
    the groups already satisfied."""
    groups = OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", [])
    seen = {e.get("event_type") for e in gated_events}
    satisfied = [g for g in groups if any(t in seen for t in g)]
    reached = len(groups) > 0 and len(satisfied) == len(groups)
    score = int(round(100 * len(satisfied) / len(groups))) if groups else 0
    labels: List[str] = []
    for g in satisfied:
        hit = next((t for t in g if t in seen), g[0])
        labels.append(_evidence_title(hit))
    return {"reached": reached, "score": score, "completed_required": labels}


def _guided_reading_only_response(module_id: str, variant_id: Optional[str] = None) -> Dict[str, Any]:
    """The ENTIRE Guided/Tutorial Mode progress contract.

    Guided Mode is reading/tutorial-only: no attack execution, no
    evidence-based mission completion, no target-agent scoring, no AI attack
    report. This function performs NO event fetching and NO evidence
    evaluation — it is a static response, by design, so nothing in Guided
    Mode can ever be mistaken for a real, scored attack. See
    docs/redteam-guided-mode-reading-only.md.
    """
    return {
        "module_id":           module_id,
        "mode":                "guided",
        "variant_id":          variant_id,
        "variant_name":        None,
        "variant_difficulty":  None,
        "variant_description": None,
        "variant_overview":    None,
        "reading_only":        True,
        "progress_percent":    0,
        "completed_tasks":     [],
        "tasks":               [],
        "evidence":            [],
        "success":             False,
        "score":               0,
        "learner_message": (
            "Guided Mode is reading-only. Switch to Operator Mode to perform "
            "the lab and generate an AI/Purple Team report."
        ),
        "defensive_insight":   None,
        "events_examined":     0,
        "brute_force_activity": None,

        # Goal-trigger model — Guided Mode never triggers a goal (reading-only).
        "goal_triggered":        False,
        "status":                "incomplete",
        "trigger_event":         None,
        "trigger_reason":        None,
        "quality_feedback":      "Guided Mode is reading-only — no goal to trigger.",
        "missing_methodology":   [],
        "observed_tools":        [],
        "report_recommendations": [],

        "objective": "Read the guided explanation, then switch to Operator Mode to perform the lab.",
        "completion_score":   0,
        "quality_score":      0,
        "completed_required": [],
        "completed_quality":  [],
        "missing_quality":    [],
        "warnings": [
            "Guided Mode is reading-only. Attack progress is available in Operator Mode.",
        ],
        "next_recommended_action": "Switch to Operator Mode when ready to practice.",
        "objective_tasks":    [],

        "raw_event_count":      0,
        "counted_event_count":  0,
        "ignored_event_count":  0,
        "ignored_reasons":      {r: 0 for r in IGNORED_REASONS},
        "last_observed_events": [],
        "last_counted_events":  [],
    }


def reading_only_progress(module_id: str, mode: str = "guided") -> Dict[str, Any]:
    """Public alias for `_guided_reading_only_response()`.

    Same static, zero-scoring payload — no event fetching, no evidence
    evaluation. Exists so callers outside `compute()` (e.g. a future endpoint
    that wants the reading-only shape without a full compute() call) have a
    stable, non-underscored name to import. `compute()` itself calls the
    private helper directly.
    """
    return _guided_reading_only_response(module_id)


def compute(module_id: str,
            mission_started_at: float,
            session_completed_steps: Optional[List[int]] = None,
            mode: str = "tutorial",
            variant_id: Optional[str] = None,
            session_id: Optional[str] = None,
            ) -> Dict[str, Any]:
    """
    Returns a learner-facing progress payload:
        {
          module_id, mode, variant_id, progress_percent, completed_tasks: [int],
          tasks: [...with .complete + .matched_events],
          evidence: [card],
          success: bool,
          learner_message, defensive_insight,
        }

    `mode` selects the product contract (see
    docs/redteam-guided-mode-reading-only.md):
      - "tutorial" (aka "guided")  → READING-ONLY. Returns a static
        reading_only=True payload immediately — no events are fetched, no
        evidence is scored, `success` is always False.
      - "lab" (aka "operator")    → the real lab pipeline: /op/ route +
        approved local-tool evidence, objective-based completion, quality
        scoring, ignored-evidence diagnostics.

    `variant_id` selects the specific attack flavour (e.g. "password_spray",
    "credential_stuffing", "hydra_targeted" for brute_force) — Operator Mode
    only. When set, the variant's tasks REPLACE the module's default ladder,
    and the variant's success_event_types REPLACE the default success
    criteria. When omitted the legacy default ladder is used.

    Legacy values "guided" and "operator" are normalised to "tutorial"/"lab".
    """
    # Normalise legacy mode names
    if mode == "guided":
        mode = "tutorial"
    elif mode == "operator":
        mode = "lab"
    if mode not in ("tutorial", "lab"):
        mode = "tutorial"

    # Guided/Tutorial Mode is reading-only — short-circuit BEFORE any event
    # fetching or evidence evaluation. This is the only Guided Mode code path;
    # nothing below this line ever runs for mode="tutorial".
    if mode == "tutorial":
        return _guided_reading_only_response(module_id, variant_id)

    spec = PROGRESS_SPECS.get(module_id)
    if not spec:
        return {
            "module_id": module_id,
            "mode": mode,
            "variant_id": variant_id,
            "progress_percent": 0,
            "completed_tasks": [],
            "tasks": [],
            "evidence": [],
            "success": False,
            "learner_message": f"No progress specification for module {module_id!r}.",
            "defensive_insight": None,
        }

    # ─── Resolve variant ────────────────────────────────────────────────
    # If a known variant is supplied, its tasks replace the default ladder
    # and its success_event_types replace the default success criteria.
    variant = get_variant_spec(module_id, variant_id)
    is_lab = True  # Operator Mode only — Guided Mode returned above.

    if variant is not None:
        task_ladder = variant["tasks"]
        variant_id_out = variant_id or next(iter(MODULE_VARIANTS.get(module_id, {})), None)
    else:
        # Legacy path — the module's default tasks_lab ladder.
        task_ladder = spec.get("tasks_lab") or spec.get("tasks", [])
        variant_id_out = None

    # Fetch ALL events since mission start — do NOT filter by module_id here.
    # Cross-module events (e.g. search_used is tagged 'xss' but counts for recon
    # task 2) must be visible. Task-level event_type matching below handles scoping.
    raw_events = fetch_events(since=mission_started_at, limit=500)

    if module_id == "brute_force":
        events_for_completion = [
            e for e in raw_events
            if _is_brute_force_event_for_completion(e, is_lab=is_lab)
        ]
        events_for_quality = [
            e for e in raw_events
            if _is_brute_force_event_for_quality(e, is_lab=is_lab)
        ]
    else:
        events_for_completion = [
            e for e in raw_events
            if _event_counts_for_completion(e, is_lab=is_lab, module_id=module_id)
        ]
        events_for_quality = [
            e for e in raw_events
            if _event_counts_for_quality(e, is_lab=is_lab, module_id=module_id)
        ]

    # Legacy task progress may include either objective-completion evidence or
    # high-quality methodology evidence. The typed objective/quality sections
    # below remain the authoritative model for success and quality_score.
    events_for_progress: List[Dict[str, Any]] = []
    _seen_event_ids: set = set()
    for _ev in [*events_for_quality, *events_for_completion]:
        _eid = id(_ev)
        if _eid not in _seen_event_ids:
            events_for_progress.append(_ev)
            _seen_event_ids.add(_eid)

    # Teaching content (TryHackMe-style) for this (module, variant), if any.
    walkthrough = get_walkthrough(module_id, variant_id_out)
    wt_sections = (walkthrough or {}).get("sections", [])

    # Build task results
    tasks_out = []
    completed_idx: List[int] = []
    for idx, t in enumerate(task_ladder):
        wanted_types = set(t["event_types"])
        matches = [e for e in events_for_progress if e.get("event_type") in wanted_types]
        min_count = t.get("min_count", 1)
        complete = len(matches) >= min_count
        if complete:
            completed_idx.append(idx)
        section = wt_sections[idx] if idx < len(wt_sections) else {}
        tasks_out.append({
            "title":          t["title"],
            "explain":        t.get("explain"),
            # Rich teaching content — falls back to `explain` when absent.
            "what":           section.get("what"),
            "how":            section.get("how") or t.get("explain"),
            "look_for":       section.get("look_for"),
            "complete":       complete,
            "match_count":    len(matches),
            "min_count":      min_count,
            "event_types":    t["event_types"],
        })

    # Gather all event_types referenced in this ladder so evidence cards
    # stay scoped to the current module (no cross-module noise in the panel).
    spec_event_types: set = set()
    for t in task_ladder:
        spec_event_types.update(t["event_types"])
    # Objective + quality event types are always in-scope so completion evidence
    # and methodology signals show as cards even when they aren't on the ladder.
    _obj = OBJECTIVE_SPECS.get(module_id, {})
    for g in _obj.get("completion_groups", []):
        spec_event_types.update(g)
    for qt in _obj.get("quality_tasks", []):
        spec_event_types.update(qt.get("event_types", []))

    # Success criteria: variant overrides default
    if variant is not None:
        variant_success = set(variant.get("success_event_types") or [])
        spec_event_types.update(variant_success)
        success_required = variant_success
    else:
        spec_event_types.update(spec.get("success_lab") or [])
        success_required = set(spec.get("success_lab") or [])

    # Build evidence cards (one per event_type, keep latest occurrence).
    # We use raw_events here (not the gated set) so a learner who clicked
    # in the browser still sees their actions — they just don't count.
    def _counts_for_completion(ev: Dict[str, Any]) -> bool:
        return (
            _is_brute_force_event_for_completion(ev, is_lab=is_lab)
            if module_id == "brute_force"
            else _event_counts_for_completion(ev, is_lab=is_lab, module_id=module_id)
        )

    def _counts_for_quality(ev: Dict[str, Any]) -> bool:
        return (
            _is_brute_force_event_for_quality(ev, is_lab=is_lab)
            if module_id == "brute_force"
            else _event_counts_for_quality(ev, is_lab=is_lab, module_id=module_id)
        )

    seen_types: set = set()
    cards: List[Dict[str, Any]] = []
    for e in reversed(raw_events):
        et = e.get("event_type")
        if et not in spec_event_types:   # skip events unrelated to this module
            continue
        if et in seen_types:
            continue
        seen_types.add(et)
        counts_for_completion = _counts_for_completion(e)
        counts_for_quality = _counts_for_quality(e)
        reason = None
        if counts_for_completion and not counts_for_quality:
            reason = "completed_objective_but_missing_tool_confirmation"
        cards.append({
            "title":       _evidence_title(et),
            "description": e.get("learner_message") or "",
            "event_type":  et,
            "timestamp":   e.get("ts"),
            "severity":    e.get("severity", "info"),
            "module_id":   e.get("module_id"),
            "via":         e.get("via", "unknown"),
            "counts":      counts_for_completion,
            "counts_for_completion": counts_for_completion,
            "counts_for_quality": counts_for_quality,
            "reason":      reason,
            "extra":       e.get("extra", {}),
        })
    cards.sort(key=lambda c: c.get("timestamp") or 0, reverse=True)

    # ── Append tool evidence from Lab Mode ──────────────────────────────────
    # If the learner used the AttackBox terminal, those commands are recorded
    # in operator_api. Merge them into evidence cards so Check Progress shows
    # a unified view of all learner activity.
    try:
        from backend import operator_api
        tool_events = operator_api.get_tool_evidence(since=mission_started_at)
        for te in tool_events:
            if session_id and te.get("session_id") and te.get("session_id") != session_id:
                continue
            # Filter by module_id if the tool command was tagged
            if te.get("module_id") and te["module_id"] != module_id:
                continue
            cards.append({
                "title":       _evidence_title(te.get("event_type", "tool_command_observed")),
                "description": te.get("learner_message", ""),
                "event_type":  te.get("event_type", "tool_command_observed"),
                "timestamp":   te.get("ts"),
                "severity":    te.get("severity", "info"),
                "module_id":   te.get("module_id"),
                "via":         te.get("via") or "attackbox",
                "counts":      True,
                "counts_for_completion": True,
                "counts_for_quality": True,
                "reason":      None,
                "extra":       {
                    "tool": te.get("tool"),
                    "command": te.get("command", "")[:80],
                    **(te.get("extra") or {}),
                },
            })
    except ImportError:
        pass  # operator_api not available — skip tool evidence
    cards.sort(key=lambda c: c.get("timestamp") or 0, reverse=True)

    # ── Goal-trigger completion (the core of the goal-trigger model) ─────────
    # The mission is COMPLETE the instant its goal event is observed on the
    # operator target — via-independent, no task ladder, no failure count, no
    # tool requirement. brute_force is no longer special-cased: a single
    # credential_found / login_success on /op/auth/login completes it, exactly
    # like every other module.
    brute_force_activity = (
        _brute_force_activity(raw_events, is_lab=is_lab)
        if module_id == "brute_force" else None
    )
    goal_triggered, trigger_event, trigger_reason = _goal_trigger(
        module_id, raw_events, is_lab=is_lab
    )
    success = goal_triggered
    completion = {
        "reached": goal_triggered,
        "score": 100 if goal_triggered else 0,
        "completed_required": [_evidence_title(trigger_event)] if goal_triggered else [],
    }

    # ── Learning QUALITY (methodology) — scored, never blocks completion ─────
    # Matched against high-quality tool events only; browser objective proof can
    # complete a mission, but it does not satisfy methodology tasks.
    quality_event_types: set = set()
    for qt in OBJECTIVE_SPECS.get(module_id, {}).get("quality_tasks", []):
        quality_event_types.update(qt.get("event_types", []))
    for g in OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", []):
        quality_event_types.update(g)
    module_known_types = spec_event_types | quality_event_types
    module_events = [e for e in raw_events if e.get("event_type") in module_known_types]
    quality_event_ids = {id(e) for e in events_for_quality}
    module_quality_events = [e for e in module_events if id(e) in quality_event_ids]
    quality = _quality_report(module_id, module_quality_events)

    # ── Report-only quality signal (never blocks completion) ─────────────────
    # observed_tools = the channels the student actually drove the attack from,
    # across every in-scope operator event (not just goal events). unknown maps
    # to an explicit "tool not captured" label so the report can call it out.
    _VIA_LABELS = {
        "attackbox":    "AttackBox (local CLI)",
        "zap_repeater": "ZAP Repeater",
        "zap_fuzzer":   "ZAP Fuzzer",
        "browser":      "Browser (manual)",
        "unknown":      "unstructured method / tool not captured",
    }
    scoped_module_events = [
        e for e in module_events
        if _event_has_operator_scope(e, is_lab=is_lab, module_id=module_id)
    ]
    observed_vias = {str(e.get("via") or "unknown") for e in scoped_module_events}
    observed_tools = [_VIA_LABELS.get(v, v) for v in sorted(observed_vias)]
    used_repeatable_tool = bool(observed_vias & OPERATOR_TOOL_VIA)
    used_unknown_channel = "unknown" in observed_vias
    browser_only = observed_vias and observed_vias.issubset({"browser"})

    # missing_methodology / report_recommendations reuse the quality rubric —
    # they describe what the student SKIPPED, purely for the report.
    missing_methodology = quality["missing"]
    report_recommendations = [m["recommendation"] for m in missing_methodology if m.get("recommendation")]

    # quality_feedback — one plain-language summary of methodology depth.
    if not success:
        quality_feedback = "Goal not triggered yet — no methodology to score."
    elif used_repeatable_tool:
        quality_feedback = (
            f"Strong methodology: you used repeatable tooling "
            f"({', '.join(sorted(observed_vias & OPERATOR_TOOL_VIA))}). "
            f"Methodology score {quality['score']}%."
        )
    elif browser_only:
        quality_feedback = (
            "Objective reached, but methodology score is low: you used only the "
            "browser/manual entry and did not demonstrate repeatable tooling "
            "(ZAP Repeater/Fuzzer or the AttackBox)."
        )
    elif used_unknown_channel:
        quality_feedback = (
            "Objective reached through an unstructured/uncaptured method. The "
            "attack worked, but methodology score is very low because no "
            "repeatable ZAP/AttackBox evidence was recorded."
        )
    else:
        quality_feedback = (
            "Objective reached. Use ZAP Repeater/Fuzzer or the AttackBox next "
            "time to raise your methodology score."
        )

    # ── Ignored-event diagnostics ────────────────────────────────────────────
    # Explain, per event, why in-scope evidence did NOT count. This makes the
    # strict operator gate transparent to students and instructors.
    def _counted(ev: Dict[str, Any]) -> bool:
        return _counts_for_completion(ev)

    def _brief(ev: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": ev.get("event_type"),
            "path":       _event_path(ev),
            "backend":    _event_backend(ev) or None,
            "via":        ev.get("via", "unknown"),
            "ts":         ev.get("ts"),
        }

    ignored_reasons: Dict[str, int] = {r: 0 for r in IGNORED_REASONS}
    ignored_total = 0
    for e in module_events:
        if _counted(e):
            continue
        reason = _ignore_reason(
            e, module_id=module_id, is_lab=is_lab, module_known_types=module_known_types
        )
        if reason:
            ignored_reasons[reason] += 1
            ignored_total += 1
    counted_events = [e for e in events_for_completion]
    last_observed_events = [_brief(e) for e in sorted(
        module_events, key=lambda x: x.get("ts") or 0, reverse=True)[:8]]
    last_counted_events = [_brief(e) for e in sorted(
        counted_events, key=lambda x: x.get("ts") or 0, reverse=True)[:8]]

    # ── Safety / channel warnings (non-blocking) ─────────────────────────────
    warnings: List[str] = []
    if is_lab:
        objective_types = {t for g in OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", []) for t in g}
        counted_ids = {id(e) for e in events_for_completion}
        uncounted_objective = [
            e for e in module_events
            if e.get("event_type") in objective_types and id(e) not in counted_ids
        ]
        if uncounted_objective and not success:
            vias = sorted({str(e.get("via") or "unknown") for e in uncounted_objective})
            warnings.append(
                "You reached the objective outside the approved channel "
                f"({', '.join(vias)}). In Operator Mode, redo it on the /op/ route "
                "through ZAP Repeater/Fuzzer or the AttackBox so it counts."
            )
        if success and used_unknown_channel:
            # Not ignored any more — the goal still counted — but flag it so the
            # report can score methodology down for unstructured evidence.
            warnings.append(
                "The goal was reached through an unstructured/uncaptured method. "
                "It still completed the mission, but your methodology score is "
                "lower — drive the attack from ZAP or the AttackBox for full credit."
            )

    # ── Next recommended action (advisory, never a solution) ─────────────────
    if success and missing_methodology:
        next_action = missing_methodology[0]["recommendation"]
    elif not success:
        next_action = OBJECTIVE_SPECS.get(module_id, {}).get("objective")
    else:
        next_action = None

    progress_percent = int(round(100 * len(completed_idx) / max(len(tasks_out), 1)))

    if success:
        # Objective reached. Distinguish a clean run from one that skipped
        # recommended methodology so the student knows they can finish now.
        if quality["missing"]:
            msg = (
                "Attack objective reached. You can view the report now, or keep "
                "improving your methodology score — "
                f"{quality['score']}% of the recommended steps were observed."
            )
        else:
            msg = "Attack objective reached with strong methodology. View your report."
    elif is_lab:
        if completion["score"] >= 50:
            msg = "Close — you're near the objective. Confirm the result through ZAP/AttackBox."
        elif completion["score"] > 0:
            msg = "Lab mode: keep driving the attack from the Terminal or ZAP toward the objective."
        else:
            msg = "Lab mode: open the Terminal or ZAP and work toward the objective."
    else:
        if completion["score"] >= 50:
            msg = "Good progress — one more step reaches the attack objective."
        elif completion["score"] > 0:
            msg = "You're on your way. Follow the recommended methodology toward the objective."
        else:
            msg = "Start the mission and interact with the target environment."

    # ── Typed tasks (backward-compatible) ────────────────────────────────────
    # Augment the existing learning ladder with id/label/done/type/reason so the
    # UI can distinguish required-objective vs recommended-quality vs optional
    # learning steps without breaking consumers that read title/complete.
    import re as _re
    objective_types = {t for g in OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", []) for t in g}
    for t in tasks_out:
        ets = set(t.get("event_types", []))
        if ets & objective_types:
            ttype = "required"
        elif ets & quality_event_types:
            ttype = "quality"
        else:
            ttype = "optional"
        t["id"] = _re.sub(r"[^a-z0-9]+", "_", (t.get("title") or "task").lower()).strip("_")
        t["label"] = t.get("title")
        t["done"] = bool(t.get("complete"))
        t["type"] = ttype
        t["reason"] = None if t.get("complete") else (
            f"Needs {t.get('min_count', 1)} matching event(s); observed {t.get('match_count', 0)}."
        )

    # A compact, explicitly-typed view: the single required objective task plus
    # the recommended quality tasks. `success` follows the required task; the
    # quality tasks feed `quality_score`.
    _completed_q_ids = {q["id"] for q in quality["completed"]}
    objective_tasks: List[Dict[str, Any]] = [{
        "id":     "objective",
        "label":  OBJECTIVE_SPECS.get(module_id, {}).get("objective") or "Reach the attack objective",
        "done":   success,
        "type":   "required",
        "reason": None if success else (next_action or "Objective not reached yet."),
    }]
    for qt in OBJECTIVE_SPECS.get(module_id, {}).get("quality_tasks", []):
        done_q = qt["id"] in _completed_q_ids
        objective_tasks.append({
            "id":     qt["id"],
            "label":  qt["label"],
            "done":   done_q,
            "type":   "quality",
            "reason": None if done_q else qt.get("recommendation"),
        })

    return {
        "module_id":           module_id,
        "mode":                mode,
        "variant_id":          variant_id_out,
        "variant_name":        (variant or {}).get("name"),
        "variant_difficulty":  (variant or {}).get("difficulty"),
        "variant_description": (variant or {}).get("description"),
        "variant_overview":    (walkthrough or {}).get("overview"),
        "progress_percent":    progress_percent,
        "completed_tasks":     completed_idx,
        "tasks":               tasks_out,
        "evidence":            cards,
        "success":             success,
        "learner_message":     msg,
        "defensive_insight":   spec.get("defensive_insight"),
        "events_examined":     len(raw_events),
        "brute_force_activity": brute_force_activity,

        # ── Goal-trigger model (authoritative) ──────────────────────────────
        # A mission is complete the instant its goal event fires on the operator
        # target, independent of tool/channel. Quality is report-only and never
        # blocks completion.
        "goal_triggered":        goal_triggered,
        "status":                "complete" if goal_triggered else "incomplete",
        "trigger_event":         trigger_event,
        "trigger_reason":        trigger_reason,
        "quality_feedback":      quality_feedback,
        "missing_methodology":   missing_methodology,
        "observed_tools":        observed_tools,
        "report_recommendations": report_recommendations,

        # ── Objective/quality fields (compat) ───────────────────────────────
        # `success` and `completion_score` are compatibility mirrors of
        # `goal_triggered`; new callers should read goal_triggered/status.
        "objective":             OBJECTIVE_SPECS.get(module_id, {}).get("objective"),
        "completion_score":      completion["score"],
        "quality_score":         quality["score"],
        "completed_required":    completion["completed_required"],
        "completed_quality":     quality["completed"],
        "missing_quality":       quality["missing"],
        "warnings":              warnings,
        "next_recommended_action": next_action,
        "objective_tasks":       objective_tasks,

        # ── Operator-gate diagnostics ───────────────────────────────────────
        # Transparency into the strict Operator gate: how many events were seen,
        # how many counted, and why the rest were ignored.
        "raw_event_count":       len(raw_events),
        "counted_event_count":   len(events_for_completion),
        "ignored_event_count":   ignored_total,
        "ignored_reasons":       ignored_reasons,
        "last_observed_events":  last_observed_events,
        "last_counted_events":   last_counted_events,
    }


def _evidence_title(event_type: Optional[str]) -> str:
    titles = {
        "portal_visited":              "Portal visited",
        "route_discovered":            "Route discovered",
        "hidden_clue_accessed":        "Hidden clue accessed",
        "login_failed":                "Failed login observed",
        "login_success":               "Successful login observed",
        "brute_force_pattern":         "Brute-force pattern detected",
        "credential_found":            "Valid credential confirmed",
        "search_used":                 "Search feature used",
        "xss_payload_observed":        "XSS-shaped payload submitted",
        "reflected_input_detected":    "Reflected input observed",
        "diagnostics_used":            "Diagnostics form used",
        "command_separator_observed":  "Shell metacharacters observed",
        "command_injection_detected":  "Command injection confirmed",
        "file_viewer_used":            "File viewer used",
        "traversal_pattern_observed":  "Path traversal observed",
        "sensitive_file_disclosed":    "Sensitive file disclosed",
        "file_upload_used":            "File upload form used",
        "file_saved":                  "File saved on the server",
        "dangerous_extension_accepted": "Dangerous extension accepted",
        "unrestricted_upload_detected": "Unrestricted upload confirmed",
        "profile_update_used":         "Profile update used",
        "csrf_token_missing":          "Profile update without a CSRF token",
        "csrf_lure_visited":           "Attacker lure page visited",
        "csrf_lure_submitted":         "Forged form submitted from lure page",
        "profile_changed_without_csrf": "Profile changed without CSRF protection",
        "tool_command_observed":       "Lab tool command executed",
        "tool_used":                   "Lab tool used",
        "zap_repeater_request":        "ZAP Repeater request sent",
        "zap_fuzzer_started":          "ZAP Fuzzer started",
        "zap_fuzzer_payload_tested":   "ZAP Fuzzer payload tested",
        "zap_fuzzer_completed":        "ZAP Fuzzer completed",
        "zap_fuzzer_match_found":      "ZAP Fuzzer match found",
        "recon_sequence_observed":     "Recon sequence detected",
    }
    return titles.get(event_type or "", str(event_type or "unknown"))
