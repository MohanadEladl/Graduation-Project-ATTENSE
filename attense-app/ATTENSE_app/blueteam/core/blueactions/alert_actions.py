"""
alert_actions.py — Alert Event Builders (Blue Team Core)
=========================================================
Pure functions that construct Event objects for all alert-related actions.
No side effects — they only build and return an Event.

The service layer calls these, then passes the event to the EventEmitter.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident


def _new_event_id() -> str:
    """Generate a short unique event identifier."""
    return f"evt-{uuid.uuid4().hex[:12]}"


def build_raise_alert_event(
    incident: Incident,
    siem_id: str,
    target_id: str,
    target_type: str,
    rule_name: str | None,
    severity: str,
    raw_log: str | None,
) -> Event:
    """
    Build an alert_raised event representing the SIEM detecting an anomaly.

    Actor: system (SIEM)
    Target: the affected host/service/account
    Outcome: detected
    """
    meta: dict = {"severity": severity}
    if rule_name:
        meta["rule_name"] = rule_name
    if raw_log:
        meta["raw_log"] = raw_log

    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=siem_id,
        target_id=target_id,
        event_type="alert_raised",
        actor_type="system",
        target_type=target_type,
        timestamp=datetime.now(),
        outcome="detected",
        metadata=meta,
    )


def build_investigate_alert_event(
    incident: Incident,
    analyst_id: str,
    alert_id: str,
    notes: str | None,
) -> Event:
    """
    Build an alert_investigation_started event representing an analyst starting triage.

    Actor: blue_team (analyst)
    Target: the alert being investigated
    Outcome: unknown (not yet determined)
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=alert_id,
        event_type="alert_investigation_started",
        actor_type="blue_team",
        target_type="alert",
        timestamp=datetime.now(),
        outcome="unknown",
        metadata={"notes": notes} if notes else None,
    )


def build_deny_alert_event(
    incident: Incident,
    analyst_id: str,
    alert_id: str,
    notes: str | None,
) -> Event:
    """
    Build an alert_denied event representing an analyst marking a false positive.

    Actor: blue_team (analyst)
    Target: the alert being denied
    Outcome: false_positive
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=alert_id,
        event_type="alert_denied",
        actor_type="blue_team",
        target_type="alert",
        timestamp=datetime.now(),
        outcome="false_positive",
        metadata={"notes": notes} if notes else None,
    )
