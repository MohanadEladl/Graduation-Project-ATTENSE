"""
target-agent/app/evidence.py — Lab evidence event store.

Every vulnerable endpoint records structured "lab events" here when learners
interact with it manually. The red-team backend polls /lab/events to compute
mission progress.

This is a small in-memory ring buffer — events live only as long as the
target-agent container does, which is fine for an educational lab.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

# ── Module-aware event ID space ──────────────────────────────────────────────
# Event types the lab knows about. Free text is allowed but these are the
# canonical strings the red-team progress matcher looks for.
EVENT_TYPES = {
    # recon
    "portal_visited", "route_discovered", "hidden_clue_accessed",
    "recon_sequence_observed",
    # brute_force
    "login_failed", "login_success", "brute_force_pattern", "credential_found",
    # xss
    "search_used", "xss_payload_observed", "reflected_input_detected",
    # cmd_injection
    "diagnostics_used", "command_separator_observed", "command_injection_detected",
    # dir_traversal
    "file_viewer_used", "traversal_pattern_observed", "sensitive_file_disclosed",
    # file_upload
    "file_upload_used", "file_saved", "dangerous_extension_accepted",
    "unrestricted_upload_detected",
    # csrf
    "profile_update_used", "csrf_token_missing", "csrf_lure_visited",
    "csrf_lure_submitted", "profile_changed_without_csrf",
}

_MAX = 5000
_lock  = threading.Lock()
_events: List[Dict[str, Any]] = []
# Per-source-IP recent activity for cross-event detection (e.g. brute force pattern)
_recent: Dict[str, List[Dict[str, Any]]] = {}


def record(
    event_type: str,
    *,
    module_id: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
    learner_message: Optional[str] = None,
    severity: str = "info",
    source_ip: Optional[str] = None,
    via: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record a structured lab event. Returns the event.

    `via` describes how the request reached the target-agent:
      - "browser"   → request came through the lab-browser proxy
                      (X-Forwarded-Prefix: /target was set)
      - "attackbox" → request came from the AttackBox container
                      (User-Agent contains "AttenseAttackBox" or
                       source_ip matches the AttackBox container hostname)
      - "unknown"   → none of the above (e.g. someone hitting the bare
                       target-agent host directly)
    Operator-mode missions only count evidence with via="attackbox".
    """
    ev = {
        "id":              len(_events),
        "ts":              time.time(),
        "event_type":      event_type,
        "module_id":       module_id,
        "path":            path,
        "method":          method,
        "severity":        severity,
        "source_ip":       source_ip,
        "via":             via or "unknown",
        "learner_message": learner_message or _DEFAULT_MSG.get(event_type),
        "extra":           dict(extra or {}),
    }
    with _lock:
        _events.append(ev)
        if len(_events) > _MAX:
            del _events[: len(_events) - _MAX]
        if source_ip:
            _recent.setdefault(source_ip, []).append(ev)
            if len(_recent[source_ip]) > 100:
                _recent[source_ip] = _recent[source_ip][-100:]
    # Cross-event detection (brute-force pattern after N failed logins)
    _detect_patterns(ev)
    return ev


# Event types that count as distinct portal areas visited (for recon detection)
_RECON_AREA_EVENTS = frozenset({
    "search_used", "diagnostics_used", "file_viewer_used",
    "file_upload_used", "profile_update_used", "route_discovered",
    "csrf_lure_visited", "hidden_clue_accessed",
})
# How many distinct areas must be visited to fire recon_sequence_observed
_RECON_THRESHOLD = 4


def _detect_patterns(ev: Dict[str, Any]) -> None:
    """Synthesize derived events after threshold activity is observed.

    Derived events:
      brute_force_pattern — 3+ failed logins from same IP in 5 minutes.
      recon_sequence_observed — 4+ distinct portal areas visited by same IP.
    """
    ip = ev.get("source_ip")
    if not ip:
        return

    # ── Brute-force pattern ──────────────────────────────────────────────────
    if ev["event_type"] == "login_failed":
        with _lock:
            recent_fails = [
                e for e in _recent.get(ip, [])
                if e["event_type"] == "login_failed" and ev["ts"] - e["ts"] <= 300
            ]
            already = any(
                e["event_type"] == "brute_force_pattern"
                and e["source_ip"] == ip
                and ev["ts"] - e["ts"] <= 300
                for e in _recent.get(ip, [])
            )
        if len(recent_fails) >= 3 and not already:
            synth = {
                "id":              len(_events),
                "ts":              time.time(),
                "event_type":      "brute_force_pattern",
                "module_id":       "brute_force",
                "path":            "/auth/login",
                "method":          "POST",
                "severity":        "high",
                "source_ip":       ip,
                # Inherit via from the triggering event so operator-mode
                # gating still works on derived events.
                "via":             ev.get("via", "unknown"),
                "learner_message": (
                    f"{len(recent_fails)} failed login attempts from this client "
                    "in the last 5 minutes — brute-force pattern detected."
                ),
                "extra":           {"failure_count": len(recent_fails)},
            }
            with _lock:
                _events.append(synth)
                _recent.setdefault(ip, []).append(synth)

    # ── Recon sequence detection ─────────────────────────────────────────────
    if ev["event_type"] in _RECON_AREA_EVENTS:
        with _lock:
            # Count distinct portal areas visited by this IP (session-wide)
            visited_types = {
                e["event_type"]
                for e in _recent.get(ip, [])
                if e["event_type"] in _RECON_AREA_EVENTS
            }
            already_recon = any(
                e["event_type"] == "recon_sequence_observed"
                and e["source_ip"] == ip
                for e in _recent.get(ip, [])
            )
        if len(visited_types) >= _RECON_THRESHOLD and not already_recon:
            synth = {
                "id":              len(_events),
                "ts":              time.time(),
                "event_type":      "recon_sequence_observed",
                "module_id":       "recon",
                "path":            "/",
                "method":          "GET",
                "severity":        "medium",
                "source_ip":       ip,
                "via":             ev.get("via", "unknown"),
                "learner_message": (
                    f"Learner visited {len(visited_types)} distinct portal areas "
                    f"({', '.join(sorted(visited_types))}) — recon sequence confirmed."
                ),
                "extra":           {"visited_areas": sorted(visited_types)},
            }
            with _lock:
                _events.append(synth)
                _recent.setdefault(ip, []).append(synth)


def list_events(*, since: float = 0.0,
                module_id: Optional[str] = None,
                via: Optional[str] = None,
                limit: int = 500) -> List[Dict[str, Any]]:
    """Return events recorded after `since` epoch seconds, optionally filtered.

    `via` filters by the channel the request came from:
      "browser" | "attackbox" | "unknown"
    """
    with _lock:
        snap = list(_events)
    out = [e for e in snap if e["ts"] >= since]
    if module_id:
        out = [e for e in out if e.get("module_id") == module_id]
    if via:
        out = [e for e in out if e.get("via") == via]
    return out[-limit:]


def reset() -> None:
    """Clear the store. Useful when a learner restarts a mission."""
    with _lock:
        _events.clear()
        _recent.clear()


# ── Default learner-friendly messages ────────────────────────────────────────
_DEFAULT_MSG: Dict[str, str] = {
    "portal_visited":              "The learner explored the portal home page.",
    "route_discovered":            "The learner navigated to a labeled application area.",
    "hidden_clue_accessed":        "The learner discovered a hidden route or clue.",
    "recon_sequence_observed":     "The learner visited 4+ distinct portal areas, confirming a recon sweep.",

    "login_failed":                "A failed login attempt was observed on /auth/login.",
    "login_success":               "A successful login was observed.",
    "brute_force_pattern":         "Multiple failed login attempts indicate brute-force activity.",
    "credential_found":            "A valid credential pair was successfully used to log in.",

    "search_used":                 "The search feature was used.",
    "xss_payload_observed":        "A script-like payload was submitted to the search feature.",
    "reflected_input_detected":    "User input was reflected back into the page without safe encoding.",

    "diagnostics_used":            "The network diagnostics form was used.",
    "command_separator_observed":  "The host parameter included shell separator characters (; | && backticks).",
    "command_injection_detected":  "Command injection behaviour was detected in the ping tool output.",

    "file_viewer_used":            "The file viewer was used.",
    "traversal_pattern_observed":  "A path-traversal sequence was submitted to the file viewer.",
    "sensitive_file_disclosed":    "A sensitive system file was disclosed by the file viewer.",

    "file_upload_used":            "The file upload form was used.",
    "file_saved":                  "An uploaded file was saved on disk.",
    "dangerous_extension_accepted":"A dangerous file extension was accepted by the upload endpoint.",
    "unrestricted_upload_detected":"The upload endpoint accepts unrestricted file types.",

    "profile_update_used":         "The profile update endpoint was used.",
    "csrf_token_missing":          "Profile update accepted a state-changing request without a CSRF token.",
    "csrf_lure_visited":           "The simulated attacker page was visited.",
    "csrf_lure_submitted":         "The simulated attacker page submitted a hidden form to the profile update endpoint.",
    "profile_changed_without_csrf":"A profile change occurred via a request that lacked a CSRF token.",
}
