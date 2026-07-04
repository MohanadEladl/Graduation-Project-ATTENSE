"""
containment_validator.py — Containment Validation Rules
=========================================================
Pre-condition checks for containment actions.
"""

from __future__ import annotations

from ATTENSE_app.incidents.incident import Incident


def validate_initiate_containment(incident: Incident, store) -> None:
    """
    Guard for initiate_containment().

    Rules:
    - Incident must be in DETECTED status (confirmed true positive).
    - A containment_initiated event must not already exist.
    """
    from config.constants import (
        STATUS_DETECTED,
        EVENT_CONTAINMENT_INITIATED,
    )
    if incident.status != STATUS_DETECTED:
        raise ValueError(
            f"Cannot initiate containment for incident '{incident.incident_id}': "
            f"expected status DETECTED, got '{incident.status}'."
        )
    if store.has_event(incident.incident_id, EVENT_CONTAINMENT_INITIATED):
        raise ValueError(
            f"Containment has already been initiated for incident '{incident.incident_id}'."
        )


def validate_complete_containment(incident: Incident, store) -> None:
    """
    Guard for complete_containment().

    Rules:
    - A containment_initiated event must exist first.
    - Incident must not already be CONTAINED or ENDED.
    - containment_succeeded/failed must not already exist.
    """
    from config.constants import (
        TERMINAL_STATUSES,
        EVENT_CONTAINMENT_INITIATED,
        EVENT_CONTAINMENT_SUCCEEDED,
        EVENT_CONTAINMENT_FAILED,
    )
    if not store.has_event(incident.incident_id, EVENT_CONTAINMENT_INITIATED):
        raise ValueError(
            f"Cannot complete containment for incident '{incident.incident_id}': "
            "containment has not been initiated yet."
        )
    if incident.status in TERMINAL_STATUSES:
        raise ValueError(
            f"Cannot complete containment for incident '{incident.incident_id}': "
            f"already in terminal status '{incident.status}'."
        )
    if store.has_event(incident.incident_id, EVENT_CONTAINMENT_SUCCEEDED) or \
       store.has_event(incident.incident_id, EVENT_CONTAINMENT_FAILED):
        raise ValueError(
            f"Containment outcome already recorded for incident '{incident.incident_id}'."
        )
