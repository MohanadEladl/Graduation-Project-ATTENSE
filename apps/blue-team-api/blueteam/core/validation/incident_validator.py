"""
incident_validator.py — Incident Validation Rules
===================================================
Pre-condition checks for incident confirmation.
"""

from __future__ import annotations

from ATTENSE_app.incidents.incident import Incident


def validate_confirm_incident(incident: Incident, store) -> None:
    """
    Guard for confirm_incident().

    Rules:
    - An alert_investigation_started event must already exist.
    - Incident must not already be confirmed, contained, or ended.
    - Incident must not have been denied (false positive path).
    """
    from ...config.constants import (
        TERMINAL_STATUSES,
        EVENT_ALERT_INVESTIGATION_STARTED,
        EVENT_INCIDENT_CONFIRMED,
        EVENT_ALERT_DENIED,
    )
    if incident.status in TERMINAL_STATUSES:
        raise ValueError(
            f"Cannot confirm incident '{incident.incident_id}': "
            f"already in terminal status '{incident.status}'."
        )
    if not store.has_event(incident.incident_id, EVENT_ALERT_INVESTIGATION_STARTED):
        raise ValueError(
            f"Cannot confirm incident '{incident.incident_id}': "
            "investigation has not started yet."
        )
    if store.has_event(incident.incident_id, EVENT_ALERT_DENIED):
        raise ValueError(
            f"Cannot confirm incident '{incident.incident_id}': "
            "alert was already denied as a false positive."
        )
    if store.has_event(incident.incident_id, EVENT_INCIDENT_CONFIRMED):
        raise ValueError(
            f"Incident '{incident.incident_id}' has already been confirmed."
        )
