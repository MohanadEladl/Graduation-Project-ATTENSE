"""
router.py — Blue Team API Router
==================================
The ONLY layer exposed to the outside world.
All external callers (Hive, frontend UI, sandbox, mapper) reach the
Blue Team THROUGH this file.

Router responsibilities (and ONLY these):
    1. Define URL endpoints
    2. Receive and validate incoming requests (schema enforced by Pydantic)
    3. Call the appropriate service
    4. Return the response

Router does NOT contain business logic — it is traffic control only.

Blue Team Workflow:
    [system] raise_alert()
                 │
                 ▼
    [human] investigate_alert()
                 │
          ┌──────┴──────┐
          ▼             ▼
    deny_alert()   confirm_incident()
    (false +ve)        │
                       ▼
              initiate_containment()
                       │
                       ▼
              complete_containment()
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, status

from .dependencies import get_event_emitter, get_hive_client, get_sandbox_connector, get_enrichment_service
from core.services.alert_service import raise_alert, investigate_alert, deny_alert
from core.services.incident_service import confirm_incident
from core.services.containment_service import initiate_containment, complete_containment
from infrastructure.eventstore.event_emitter import EventEmitter
from infrastructure.thehive.hive_client import HiveClient
from infrastructure.sandbox.target_connector import TargetConnector
from infrastructure.cortex.enrichment_service import EnrichmentService
from schemas.requests.alert_requests import (
    RaiseAlertRequest,
    InvestigateAlertRequest,
    DenyAlertRequest,
)
from schemas.requests.incident_requests import ConfirmIncidentRequest
from schemas.requests.containment_requests import (
    InitiateContainmentRequest,
    CompleteContainmentRequest,
)
from schemas.responses.action_response import ActionResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blueteam", tags=["Blue Team"])


# ─────────────────────────────────────────────────────────────────────────────
# System / SIEM Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/raise-alert",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="SIEM raises an alert for a detected anomaly",
)
def api_raise_alert(
    body: RaiseAlertRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
    hive: HiveClient = Depends(get_hive_client),
    enrichment_svc: EnrichmentService = Depends(get_enrichment_service),
) -> ActionResponse:
    """
    Simulates the SIEM detecting an anomaly and raising an alert.
    This triggers the Blue Team investigation window.

    After the alert is stored, Cortex-Lite automatically enriches any
    IOCs found in the raw log (IP reputation via AbuseIPDB, threat
    intelligence via VirusTotal). The enrichment result is attached to
    the response so the analyst has context before starting triage.

    Emits: `alert_raised`
    """
    try:
        # ── Cortex-Lite: auto-enrich IOCs from the raw alert log ─────────────
        enrichment_report = enrichment_svc.enrich_alert(
            raw_log=body.raw_log,
            siem_id=body.siem_id,
            target_id=body.target_id,
        )
        response = raise_alert(
            body=body,
            emitter=emitter,
            hive=hive,
            enrichment_report=enrichment_report,
        )
        response.enrichment = enrichment_report.to_dict()
        return response
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Blue Team Analyst Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/investigate-alert",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst begins investigating a raised alert",
)
def api_investigate_alert(
    body: InvestigateAlertRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
) -> ActionResponse:
    """
    Analyst picks up an alert and starts triage.

    Emits: `alert_investigation_started`
    """
    try:
        return investigate_alert(body=body, emitter=emitter)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/deny-alert",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst marks an alert as a false positive",
)
def api_deny_alert(
    body: DenyAlertRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
) -> ActionResponse:
    """
    Analyst determines the alert is a false positive. Incident ends here — no TTD recorded.

    Emits: `alert_denied`
    """
    try:
        return deny_alert(body=body, emitter=emitter)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/confirm-incident",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst confirms alert is a true positive — TTD is calculated here",
)
def api_confirm_incident(
    body: ConfirmIncidentRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
    hive: HiveClient = Depends(get_hive_client),
) -> ActionResponse:
    """
    Promotes alert to a confirmed incident. TTD (Time to Detect) is calculated at this point.

    Emits: `incident_confirmed`  →  status becomes `DETECTED`
    """
    try:
        return confirm_incident(body=body, emitter=emitter, hive=hive)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/initiate-containment",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst initiates a containment action against a target",
)
def api_initiate_containment(
    body: InitiateContainmentRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
    sandbox: TargetConnector = Depends(get_sandbox_connector),
) -> ActionResponse:
    """
    Analyst starts a containment action. Action depends on attack type:
    - Command Injection → kill process / isolate host
    - XSS              → block request / disable endpoint
    - Directory Traversal → block path / restrict access
    - Broken Auth      → lock account / invalidate session

    Emits: `containment_initiated`
    """
    try:
        return initiate_containment(body=body, emitter=emitter, sandbox=sandbox)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/complete-containment",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    summary="System records the final containment outcome",
)
def api_complete_containment(
    body: CompleteContainmentRequest,
    emitter: EventEmitter = Depends(get_event_emitter),
) -> ActionResponse:
    """
    System evaluates whether containment succeeded based on target correctness and timing.

    Emits: `containment_succeeded` | `containment_failed`
    On success → status becomes `CONTAINED`
    """
    try:
        return complete_containment(body=body, emitter=emitter)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
