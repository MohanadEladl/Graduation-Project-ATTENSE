"""
containment_actions.py — Containment Event Builders
=====================================================
Pure functions that construct Event objects for the containment phase.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident


def _new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def build_initiate_containment_event(
    incident: Incident,
    analyst_id: str,
    target_id: str,
    target_type: str,
    strategy: str | None,
) -> Event:
    """
    Build a containment_initiated event.

    Represents an analyst triggering a containment action.
    Strategy maps to the attack type:
        command_injection  → kill_process | disable_service | isolate_host
        xss                → block_request | remove_payload | disable_endpoint
        directory_traversal→ block_path | restrict_access
        broken_auth        → lock_account | invalidate_session

    Actor: blue_team (analyst)
    Outcome: None (outcome not yet known at initiation)
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=target_id,
        event_type="containment_initiated",
        actor_type="blue_team",
        target_type=target_type,
        timestamp=datetime.now(),
        outcome=None,
        metadata={"strategy": strategy} if strategy else None,
    )


def build_complete_containment_event(
    incident: Incident,
    analyst_id: str,
    target_id: str,
    target_type: str,
    event_type: str,
    outcome: str,
    notes: str | None,
) -> Event:
    """
    Build a containment_succeeded or containment_failed event.

    Outcome is supplied by the system (containment_service.py) after evaluation:
        success  → correct target, within time threshold
        partial  → correct target, but response was slow
        failure  → wrong target contained

    Actor: blue_team (analyst)
    """
    return Event(
        event_id=_new_event_id(),
        incident_id=incident.incident_id,
        scenario_id=incident.scenario_id,
        actor_id=analyst_id,
        target_id=target_id,
        event_type=event_type,
        actor_type="blue_team",
        target_type=target_type,
        timestamp=datetime.now(),
        outcome=outcome,
        metadata={"notes": notes, "system_evaluated": True} if notes
                 else {"system_evaluated": True},
    )
