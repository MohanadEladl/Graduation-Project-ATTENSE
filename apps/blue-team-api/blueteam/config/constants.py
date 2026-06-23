"""
constants.py — Shared System Constants
=========================================
Single source of truth for all allowed values used across
the Blue Team service. Import from here — never hardcode strings.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Incident Lifecycle Statuses
# ─────────────────────────────────────────────────────────────────────────────
STATUS_NOT_STARTED       = "NOT_STARTED"
STATUS_ACTIVE_UNDETECTED = "ACTIVE_UNDETECTED"
STATUS_DETECTED          = "DETECTED"
STATUS_CONTAINED         = "CONTAINED"
STATUS_ENDED             = "ENDED"

TERMINAL_STATUSES = {STATUS_CONTAINED, STATUS_ENDED}

# ─────────────────────────────────────────────────────────────────────────────
# Allowed Event Types
# ─────────────────────────────────────────────────────────────────────────────
EVENT_MALICIOUS_ACTION_EXECUTED    = "malicious_action_executed"
EVENT_ALERT_RAISED                 = "alert_raised"
EVENT_ALERT_INVESTIGATION_STARTED  = "alert_investigation_started"
EVENT_ALERT_DENIED                 = "alert_denied"
EVENT_INCIDENT_CONFIRMED           = "incident_confirmed"
EVENT_CONTAINMENT_INITIATED        = "containment_initiated"
EVENT_CONTAINMENT_SUCCEEDED        = "containment_succeeded"
EVENT_CONTAINMENT_FAILED           = "containment_failed"
EVENT_INCIDENT_ENDED               = "incident_ended"

ALLOWED_EVENT_TYPES = {
    EVENT_MALICIOUS_ACTION_EXECUTED,
    EVENT_ALERT_RAISED,
    EVENT_ALERT_INVESTIGATION_STARTED,
    EVENT_ALERT_DENIED,
    EVENT_INCIDENT_CONFIRMED,
    EVENT_CONTAINMENT_INITIATED,
    EVENT_CONTAINMENT_SUCCEEDED,
    EVENT_CONTAINMENT_FAILED,
    EVENT_INCIDENT_ENDED,
}

# ─────────────────────────────────────────────────────────────────────────────
# Actor & Target Types
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_ACTOR_TYPES  = {"red_team", "blue_team", "system"}
ALLOWED_TARGET_TYPES = {"host", "service", "account", "alert"}

# ─────────────────────────────────────────────────────────────────────────────
# Allowed Outcomes
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_OUTCOMES = {"success", "failure", "partial", "detected",
                    "blocked", "allowed", "unknown", "false_positive"}

# ─────────────────────────────────────────────────────────────────────────────
# Containment Strategies by Attack Type
# ─────────────────────────────────────────────────────────────────────────────
CONTAINMENT_STRATEGIES = {
    "command_injection":   ["kill_process", "disable_service", "isolate_host"],
    "xss":                 ["block_request", "remove_payload", "disable_endpoint"],
    "directory_traversal": ["block_path", "restrict_access"],
    "broken_auth":         ["lock_account", "invalidate_session"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Timing Thresholds (seconds)
# ─────────────────────────────────────────────────────────────────────────────
CONTAINMENT_LATE_THRESHOLD_SECONDS = 300   # 5 minutes → partial success
CONTAINMENT_INVESTIGATION_MIN_SECONDS = 5  # gap below this since investigation start → flagged premature
