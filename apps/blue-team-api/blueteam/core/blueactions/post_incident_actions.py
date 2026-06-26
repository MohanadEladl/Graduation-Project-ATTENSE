"""
post_incident_actions.py — Post-Containment Event Builders
============================================================
Pure functions that construct Event objects for the five v2.0.0 lifecycle
events that occur after initial containment:

    evidence_preserved       — analyst documented and archived forensic artifacts
    eradication_completed    — analyst removed all malicious artifacts / access vectors
    recovery_validated       — analyst confirmed service health before closing
    dismissal_approved       — a second analyst/lead approved a prior alert dismissal
    lessons_learned_recorded — post-incident review recorded and distributed

All functions follow the same pattern as containment_actions.py / investigation_actions.py:
no side effects, return an Event ready to pass to EventEmitter.emit().
"""

from __future__ import annotations

import uuid
from datetime import datetime

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident


def _new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def build_evidence_preserved_event(
    incident: Incident,
    analyst_id: str,
    notes: str | None = None,
) -> Event:
    """
    Build an evidence_preserved event.

    Represents the analyst archiving logs, hashing artifacts, and establishing
    chain-of-custody documentation after containment.

    Actor: blue_team (analyst)
    Target: the service/host from which evidence was collected
    Outcome: success
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id="evidence-store",
        event_type="evidence_preserved",
        actor_type="blue_team",
        target_type="service",
        timestamp=datetime.now(),
        outcome="success",
        metadata={"notes": notes} if notes else None,
    )


def build_eradication_completed_event(
    incident: Incident,
    analyst_id: str,
    notes: str | None = None,
) -> Event:
    """
    Build an eradication_completed event.

    Represents the analyst removing all malicious artifacts, disabling backdoor
    services/accounts, and confirming the attack vector is closed.

    Actor: blue_team (analyst)
    Target: the affected service/host
    Outcome: success
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id="sandbox-target",
        event_type="eradication_completed",
        actor_type="blue_team",
        target_type="service",
        timestamp=datetime.now(),
        outcome="success",
        metadata={"notes": notes} if notes else None,
    )


def build_recovery_validated_event(
    incident: Incident,
    analyst_id: str,
    notes: str | None = None,
) -> Event:
    """
    Build a recovery_validated event.

    Represents the analyst running health checks, service-status probes, and
    functional tests confirming normal operation has been restored before
    closing the incident.

    Actor: blue_team (analyst)
    Target: the recovered service/host
    Outcome: success
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id="sandbox-target",
        event_type="recovery_validated",
        actor_type="blue_team",
        target_type="service",
        timestamp=datetime.now(),
        outcome="success",
        metadata={"notes": notes} if notes else None,
    )


def build_dismissal_approved_event(
    incident: Incident,
    approver_id: str,
    alert_id: str,
    notes: str | None = None,
) -> Event:
    """
    Build a dismissal_approved event.

    Represents a SECOND analyst / team lead approving a prior alert dismissal.
    The approver_id MUST differ from the actor_id on the preceding alert_denied
    event — this is enforced by the webhook router's _check_dismissal_approval()
    guard before this event is emitted.

    Actor: blue_team (approving analyst/lead)
    Target: the alert being approved for dismissal
    Outcome: success
    """
    meta: dict = {"approved_by": approver_id}
    if notes:
        meta["notes"] = notes

    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=approver_id,
        target_id=alert_id,
        event_type="dismissal_approved",
        actor_type="blue_team",
        target_type="alert",
        timestamp=datetime.now(),
        outcome="success",
        metadata=meta,
    )


def build_lessons_learned_event(
    incident: Incident,
    analyst_id: str,
    notes: str | None = None,
) -> Event:
    """
    Build a lessons_learned_recorded event.

    Represents the post-incident review being completed and recorded —
    root causes identified, response gaps noted, improvement actions assigned.

    Actor: blue_team (analyst / incident commander)
    Target: the incident record
    Outcome: success
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=incident.incident_id,
        event_type="lessons_learned_recorded",
        actor_type="blue_team",
        target_type="alert",
        timestamp=datetime.now(),
        outcome="success",
        metadata={"notes": notes} if notes else None,
    )
