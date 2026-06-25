"""
alert_validator.py — Alert Validation Rules
=============================================
Pre-condition checks for all alert-related actions.
INVALID requests die at the gate — they never reach the Blue Team core.

Raises ValueError with a descriptive message on any violation.
"""

from __future__ import annotations

from ATTENSE_app.incidents.incident import Incident


def validate_raise_alert(incident: Incident, store) -> None:
    """
    Guard for raise_alert().

    Rules:
    - Incident must not be in a terminal state (CONTAINED or ENDED).
    - An alert_raised event must not already exist for this incident.
    """
    from ...config.constants import TERMINAL_STATUSES, EVENT_ALERT_RAISED
    if incident.status in TERMINAL_STATUSES:
        raise ValueError(
            f"Cannot raise alert on incident '{incident.incident_id}': "
            f"already in terminal status '{incident.status}'."
        )
    if store.has_event(incident.incident_id, EVENT_ALERT_RAISED):
        raise ValueError(
            f"An alert has already been raised for incident '{incident.incident_id}'."
        )


def validate_investigate_alert(incident: Incident, store) -> None:
    """
    Guard for investigate_alert().

    Rules:
    - Incident must not be in a terminal state.
    - An alert_raised event must exist (can't investigate what wasn't raised).
    - An alert_investigation_started event must NOT already exist.
    """
    from ...config.constants import (
        TERMINAL_STATUSES,
        EVENT_ALERT_RAISED,
        EVENT_ALERT_INVESTIGATION_STARTED,
    )
    if incident.status in TERMINAL_STATUSES:
        raise ValueError(
            f"Cannot investigate alert for incident '{incident.incident_id}': "
            f"already in terminal status '{incident.status}'."
        )
    if not store.has_event(incident.incident_id, EVENT_ALERT_RAISED):
        raise ValueError(
            f"No alert has been raised for incident '{incident.incident_id}' yet."
        )
    if store.has_event(incident.incident_id, EVENT_ALERT_INVESTIGATION_STARTED):
        raise ValueError(
            f"Alert for incident '{incident.incident_id}' is already under investigation."
        )


def validate_deny_alert(incident: Incident, store) -> None:
    """
    Guard for deny_alert().

    Rules:
    - An alert_investigation_started event must exist first.
    - Incident must not already be confirmed or in a terminal state.
    """
    from ...config.constants import (
        TERMINAL_STATUSES,
        EVENT_ALERT_INVESTIGATION_STARTED,
        EVENT_INCIDENT_CONFIRMED,
    )
    if incident.status in TERMINAL_STATUSES:
        raise ValueError(
            f"Cannot deny alert for incident '{incident.incident_id}': "
            f"already in terminal status '{incident.status}'."
        )
    if not store.has_event(incident.incident_id, EVENT_ALERT_INVESTIGATION_STARTED):
        raise ValueError(
            f"Cannot deny alert for incident '{incident.incident_id}': "
            "investigation has not started yet."
        )
    if store.has_event(incident.incident_id, EVENT_INCIDENT_CONFIRMED):
        raise ValueError(
            f"Incident '{incident.incident_id}' has already been confirmed — cannot deny."
        )
