"""Explicit incident state-transition table (report Simplification #2).

The authoritative incident state is still computed by the legacy
`Incident.apply_event` (reused by `IncidentProjection`, so behaviour stays
exactly as the Phase 1 characterization tests pin it). This table is the
*explicit, testable* description of the expected forward progression, used to
flag events that arrive out of the expected order so they can be recorded with a
reason instead of silently corrupting metrics (e.g. a containment before any
detection — the negative-TTC bug Phase 1 documented).

It is advisory: anomalies are reported, not rejected, this phase. Rejecting or
quarantining invalid transitions is a deliberate later decision.
"""
from __future__ import annotations

from attense_core.models.constants import EventType, IncidentStatus

# status -> the event types that are an expected (in-order) next step from it.
EXPECTED_NEXT: dict[str, set[str]] = {
    IncidentStatus.NOT_STARTED.value: {
        EventType.MALICIOUS_ACTION_EXECUTED.value,
        EventType.ALERT_RAISED.value,
        EventType.ALERT_INVESTIGATION_STARTED.value,
        EventType.INCIDENT_CONFIRMED.value,
        EventType.ALERT_DENIED.value,
    },
    IncidentStatus.ACTIVE_UNDETECTED.value: {
        EventType.MALICIOUS_ACTION_EXECUTED.value,
        EventType.ALERT_RAISED.value,
        EventType.ALERT_INVESTIGATION_STARTED.value,
        EventType.INCIDENT_CONFIRMED.value,
        EventType.ALERT_DENIED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        EventType.ALERT_RAISED.value,
        EventType.INCIDENT_CONFIRMED.value,
        EventType.ALERT_DENIED.value,
        EventType.CONTAINMENT_INITIATED.value,
    },
    IncidentStatus.DETECTED.value: {
        EventType.ALERT_INVESTIGATION_STARTED.value,
        EventType.CONTAINMENT_INITIATED.value,
        EventType.CONTAINMENT_SUCCEEDED.value,
        EventType.CONTAINMENT_FAILED.value,
        EventType.INCIDENT_ENDED.value,
    },
    IncidentStatus.CONTAINING.value: {
        EventType.CONTAINMENT_SUCCEEDED.value,
        EventType.CONTAINMENT_FAILED.value,
        EventType.INCIDENT_ENDED.value,
    },
    IncidentStatus.CONTAINMENT_FAILED.value: {
        EventType.CONTAINMENT_INITIATED.value,
        EventType.CONTAINMENT_SUCCEEDED.value,
        EventType.INCIDENT_ENDED.value,
    },
    IncidentStatus.CONTAINED.value: {
        EventType.INCIDENT_ENDED.value,
    },
    IncidentStatus.FALSE_POSITIVE.value: {
        EventType.INCIDENT_ENDED.value,
    },
    IncidentStatus.ENDED.value: set(),  # terminal
}


def is_expected(status: str, event_type: str) -> bool:
    """True if `event_type` is an expected in-order step from `status`."""
    return event_type in EXPECTED_NEXT.get(status, set())
