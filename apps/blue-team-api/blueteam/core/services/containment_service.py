"""
containment_service.py — Containment Service (Blue Team Core)
==============================================================
Handles the containment phase — any action that stops attack progression.

Containment is scenario-specific:
    💥 Command Injection  → kill_process, disable_service, isolate_host
    🌐 XSS               → block_request, remove_payload, disable_endpoint
    📂 Directory Traversal→ block_path, restrict_access
    🔐 Broken Auth        → lock_account, invalidate_session

initiate_containment()
    - Analyst triggers a containment action
    - Sandbox connector executes the action on the target
    - Emits: containment_initiated

complete_containment()
    - System evaluates outcome based on target correctness and response time
    - Emits: containment_succeeded | containment_failed
    - On success → status becomes CONTAINED, TTC recorded
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ...config.constants import CONTAINMENT_LATE_THRESHOLD_SECONDS
from ..blueactions.containment_actions import (
    build_initiate_containment_event,
    build_complete_containment_event,
)
from ..validation.containment_validator import (
    validate_initiate_containment,
    validate_complete_containment,
)
from ...infrastructure.eventstore.event_emitter import EventEmitter
from ...infrastructure.sandbox.target_connector import TargetConnector
from ...schemas.requests.containment_requests import (
    InitiateContainmentRequest,
    CompleteContainmentRequest,
)
from ...schemas.responses.action_response import ActionResponse

logger = logging.getLogger(__name__)


def initiate_containment(
    body: InitiateContainmentRequest,
    emitter: EventEmitter,
    sandbox: TargetConnector,
    room_id: str,
) -> ActionResponse:
    """
    Analyst starts a containment action against a specific target.

    Pre-condition: incident must be in DETECTED status.
    Side-effect: sandbox connector sends the isolation/block command to the target host.
    Emits: containment_initiated
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
    validate_initiate_containment(incident, store)

    # Instruct sandbox to perform the containment action
    try:
        sandbox.execute_containment(
            target_id=body.target_id,
            strategy=body.strategy,
        )
    except Exception as exc:
        logger.warning("[ContainmentService] Sandbox action failed (non-fatal): %s", exc)

    event = build_initiate_containment_event(
        incident=incident,
        analyst_id=body.analyst_id,
        target_id=body.target_id,
        target_type=body.target_type,
        strategy=body.strategy,
    )
    emitter.emit(incident, store, event)

    logger.info(
        "[ContainmentService] Analyst '%s' INITIATED containment on '%s' "
        "(strategy=%s) for incident '%s'.",
        body.analyst_id, body.target_id, body.strategy, incident.incident_id,
    )
    return ActionResponse.from_event(incident, event,
        f"Containment initiated on '{body.target_id}' (strategy={body.strategy}).")


def complete_containment(
    body: CompleteContainmentRequest,
    emitter: EventEmitter,
    room_id: str,
) -> ActionResponse:
    """
    System evaluates whether containment succeeded.

    Outcome is determined by the system (not the analyst) based on:
    - Target correctness: did the analyst contain the right resource?
    - Timing: was containment performed within the threshold?

    Emits: containment_succeeded (outcome=success|partial) | containment_failed
    On success → status becomes CONTAINED, TTC is recorded.
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
    validate_complete_containment(incident, store)

    # Determine correct targets from prior attack/alert events
    attack_events = [
        e for e in incident.events
        if e.event_type in ("malicious_action_executed", "alert_raised")
    ]
    correct_targets = {e.target_id for e in attack_events}
    is_correct_target = body.target_id in correct_targets if correct_targets else True

    if is_correct_target:
        start = incident.start_time or incident.detection_time
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        elapsed = (now - start.replace(tzinfo=None)).total_seconds() if start else 0
        outcome = "partial" if elapsed > CONTAINMENT_LATE_THRESHOLD_SECONDS else "success"
        event_type = "containment_succeeded"
    else:
        outcome = "failure"
        event_type = "containment_failed"

    event = build_complete_containment_event(
        incident=incident,
        analyst_id=body.analyst_id,
        target_id=body.target_id,
        target_type=body.target_type,
        event_type=event_type,
        outcome=outcome,
        notes=body.notes,
    )
    emitter.emit(incident, store, event)

    label = "SUCCEEDED" if event_type == "containment_succeeded" else "FAILED"
    logger.info(
        "[ContainmentService] Containment %s for incident '%s' (outcome=%s).",
        label, incident.incident_id, outcome,
    )
    return ActionResponse.from_event(incident, event,
        f"Containment {label.lower()} for incident '{body.incident_id}' (outcome={outcome}).")
