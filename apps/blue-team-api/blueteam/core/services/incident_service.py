"""
incident_service.py — Incident Service (Blue Team Core)
=========================================================
Handles incident confirmation — the critical step where:
    - A true positive is established
    - TTD (Time to Detect) is calculated
      TTD = incident_confirmed.timestamp − malicious_action_executed.timestamp

Called by: human analyst after investigation.
Pre-condition: alert_investigation_started must already exist.
Emits: incident_confirmed  →  status becomes DETECTED
"""

from __future__ import annotations

import logging

from ..blueactions.investigation_actions import build_confirm_incident_event
from ..validation.incident_validator import validate_confirm_incident
from ...infrastructure.eventstore.event_emitter import EventEmitter
from ...infrastructure.thehive.hive_client import HiveClient
from ...schemas.requests.incident_requests import ConfirmIncidentRequest
from ...schemas.responses.action_response import ActionResponse

logger = logging.getLogger(__name__)


def confirm_incident(
    body: ConfirmIncidentRequest,
    emitter: EventEmitter,
    hive: HiveClient,
    room_id: str,
) -> ActionResponse:
    """
    Analyst confirms the alert is a true positive.

    This is the CRITICAL decision point:
    - TTD is calculated here (start_time → confirmation timestamp)
    - Incident status transitions to DETECTED
    - Hive case is updated to reflect the escalation

    Emits: incident_confirmed
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
    validate_confirm_incident(incident, store)

    event = build_confirm_incident_event(
        incident=incident,
        analyst_id=body.analyst_id,
        alert_id=body.alert_id,
        severity=body.severity,
        notes=body.notes,
    )
    emitter.emit(incident, store, event)

    # Notify Hive that the incident has been escalated
    try:
        hive.update_case_severity(
            incident_id=incident.incident_id,
            severity=body.severity,
        )
    except Exception as exc:
        logger.warning("[IncidentService] Hive update failed (non-fatal): %s", exc)

    logger.info(
        "[IncidentService] Analyst '%s' CONFIRMED incident '%s' (severity=%s). TTD anchor set.",
        body.analyst_id, incident.incident_id, body.severity,
    )
    return ActionResponse.from_event(incident, event,
        f"Incident '{body.incident_id}' confirmed (severity={body.severity}). TTD calculated.")
