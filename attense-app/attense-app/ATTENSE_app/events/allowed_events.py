ALLOWED_EVENT_TYPES = {
    "malicious_action_executed",
    "alert_raised",
    "alert_investigation_started",
    "incident_confirmed",
    "alert_denied",
    "containment_initiated",
    "containment_succeeded",
    "containment_failed",
    "incident_ended",
}
ALLOWED_ACTOR_TYPES = {
    "red_team",
    "blue_team",
    "system",
}

ALLOWED_TARGET_TYPES = {
    "host",
    "service",
    "account",
    "alert",
}

ALLOWED_OUTCOMES = {
    "success",
    "failure",
    "partial",
    "detected",
    "blocked",
    "allowed",
    "unknown",
    "false_positive",
}
