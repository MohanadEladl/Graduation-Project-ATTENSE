"""
containment_validator.py - Containment Validation Rules
=========================================================
Pre-condition checks for containment actions.
"""

from __future__ import annotations

from attense_core.models.incident import Incident


def validate_initiate_containment(incident: Incident, store) -> None:
    """
    Guard for initiate_containment().

    Rules:
    - Incident must be in DETECTED status (confirmed true positive) - the
      first attempt - or CONTAINMENT_FAILED, so an analyst who contained the
      wrong target can retry against the correct one instead of being stuck.
      (No "already initiated" check: a retry is expected to already have a
      prior containment_initiated event from the failed attempt. The status
      check alone still blocks re-initiating while CONTAINING/CONTAINED/ENDED.)
    """
    from ...config.constants import (
        STATUS_DETECTED,
        STATUS_CONTAINMENT_FAILED,
    )
    if incident.status not in (STATUS_DETECTED, STATUS_CONTAINMENT_FAILED):
        raise ValueError(
            f"Cannot initiate containment for incident '{incident.incident_id}': "
            f"expected status DETECTED or CONTAINMENT_FAILED, got '{incident.status}'."
        )


def validate_complete_containment(incident: Incident, store) -> None:
    """
    Guard for complete_containment().

    Rules:
    - A containment_initiated event must exist first.
    - Incident must not already be CONTAINED or ENDED.
    - containment_succeeded must not already exist (that outcome is final -
      also already covered by the CONTAINED terminal-status check below, kept
      here too for defense in depth). A prior containment_failed does NOT
      block this: that's exactly the retry case initiate_containment now
      allows, and this call evaluates the analyst's latest chosen target.
    """
    from ...config.constants import (
        TERMINAL_STATUSES,
        EVENT_CONTAINMENT_INITIATED,
        EVENT_CONTAINMENT_SUCCEEDED,
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
    if store.has_event(incident.incident_id, EVENT_CONTAINMENT_SUCCEEDED):
        raise ValueError(
            f"Containment outcome already recorded for incident '{incident.incident_id}'."
        )

