"""Canonical enumerations for the ATTENSE event contract.

Phase 2 of ATTENSE_Refactoring_Optimization_Report.md ("Make the Pydantic event
model the only schema authority"): one place that defines the allowed event
types, actor types, target types, outcomes, incident states, and event sources.

The string *values* here are deliberately identical to the literals the legacy
`attense_core.models.event.Event` and `attense_core.models.incident.Incident`
already use, so `StandardEvent` can be adapted down to the legacy `Event` (and
the existing incident state machine) without changing any behaviour. The Phase 1
characterization tests pin those literals; `test_standard_event.py` asserts these
enums stay in sync with them.

`allowed_events.py` keeps the original `ALLOWED_*` sets for the legacy `Event`
validator; this module is the typed, single-source-of-truth replacement that the
new contract and (Phase 3) the incident projection build on.
"""
from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    """Lifecycle event types. Values match allowed_events.ALLOWED_EVENT_TYPES."""

    MALICIOUS_ACTION_EXECUTED = "malicious_action_executed"
    ALERT_RAISED = "alert_raised"
    ALERT_INVESTIGATION_STARTED = "alert_investigation_started"
    INCIDENT_CONFIRMED = "incident_confirmed"
    ALERT_DENIED = "alert_denied"
    CONTAINMENT_INITIATED = "containment_initiated"
    CONTAINMENT_FAILED = "containment_failed"
    CONTAINMENT_SUCCEEDED = "containment_succeeded"
    INCIDENT_ENDED = "incident_ended"
    # v2.0.0 post-containment / analyst-response types (watcher + report
    # pipeline). Scored by the evaluation pipeline; they are not incident
    # state-machine transitions (apply_event ignores them).
    EVIDENCE_PRESERVED = "evidence_preserved"
    ERADICATION_COMPLETED = "eradication_completed"
    RECOVERY_VALIDATED = "recovery_validated"
    DISMISSAL_APPROVED = "dismissal_approved"
    LESSONS_LEARNED_RECORDED = "lessons_learned_recorded"


class ActorType(str, Enum):
    """Who performed the action. Matches allowed_events.ALLOWED_ACTOR_TYPES."""

    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    SYSTEM = "system"


class TargetType(str, Enum):
    """What was acted upon. Matches allowed_events.ALLOWED_TARGET_TYPES."""

    HOST = "host"
    SERVICE = "service"
    ACCOUNT = "account"
    ALERT = "alert"


class Outcome(str, Enum):
    """Result of the event. Matches allowed_events.ALLOWED_OUTCOMES."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    DETECTED = "detected"
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    UNKNOWN = "unknown"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    """Canonical incident-projection states.

    Values match the status strings produced today by
    `attense_core.models.incident.Incident.apply_event` (pinned by the Phase 1
    characterization tests). Consumed by the Phase 3 incident projection /
    state-machine table; not carried on an event.
    """

    NOT_STARTED = "NOT_STARTED"
    ACTIVE_UNDETECTED = "ACTIVE_UNDETECTED"
    INVESTIGATING = "INVESTIGATING"
    DETECTED = "DETECTED"
    CONTAINING = "CONTAINING"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
    CONTAINED = "CONTAINED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ENDED = "ENDED"


class EventSource(str, Enum):
    """The producing system/service for an event (report Phase 2: `source`).

    Distinct from `actor_type`: `actor_type` is who acted in the exercise,
    `source` is which ATTENSE component emitted the event record.
    """

    RED_TEAM = "red-team"
    SIGNAL_STORE = "signal-store"
    BLUE_TEAM = "blue-team"
    CONTROL_API = "control-api"
    TEST = "test"
    UNKNOWN = "unknown"


__all__ = [
    "EventType",
    "ActorType",
    "TargetType",
    "Outcome",
    "IncidentStatus",
    "EventSource",
]
