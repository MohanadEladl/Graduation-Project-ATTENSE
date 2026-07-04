"""
investigation_actions.py — Investigation & Incident Event Builders
===================================================================
Pure functions that construct Event objects for investigation and
incident confirmation actions.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident


def _new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def build_confirm_incident_event(
    incident: Incident,
    analyst_id: str,
    alert_id: str,
    severity: str,
    notes: str | None,
) -> Event:
    """
    Build an incident_confirmed event representing a true-positive escalation.

    This is the CRITICAL TTD anchor:
    TTD = this event's timestamp − malicious_action_executed timestamp

    Actor: blue_team (analyst)
    Target: the alert being confirmed
    Outcome: detected
    """
    meta: dict = {"severity": severity}
    if notes:
        meta["notes"] = notes

    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=alert_id,
        event_type="incident_confirmed",
        actor_type="blue_team",
        target_type="alert",
        timestamp=datetime.now(),
        outcome="detected",
        metadata=meta,
    )
