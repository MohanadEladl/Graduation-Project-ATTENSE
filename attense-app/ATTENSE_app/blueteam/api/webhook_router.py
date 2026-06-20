"""
webhook_router.py — BlueTeam Internal Webhook Receiver
=======================================================
Receives POST events emitted by TheHive when analysts act in the Hive UI.

Since TheHive runs inside the SAME container ( supervisord),
it communicates with this endpoint via localhost:

    TheHive notifier → POST http://localhost:8010/internal/webhook/hive

This endpoint is INTERNAL to the BlueTeam component.
ATTENSE Core never calls it — it is Hive calling back into BlueTeam.

Flow:
    Analyst action in Hive UI
    → Hive emits webhook
    → POST /internal/webhook/hive
    → HiveEventTranslator.extract_incident_id() + translate()
    → ATTENSE Event created
    → EventEmitter.emit() → incident state / metrics updated
"""

from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .dependencies import get_event_emitter, get_attacker_log_attacher, get_settings
from config.settings import Settings
from config.constants import CONTAINMENT_INVESTIGATION_MIN_SECONDS
from core.blueactions.hive_event_translator import HiveEventTranslator
from core.blueactions.attacker_log_attacher import AttackerLogAttacher
from infrastructure.eventstore.event_emitter import EventEmitter

logger = logging.getLogger(__name__)

webhook_router = APIRouter(
    prefix="/internal/webhook",
    tags=["Webhook (Internal — Hive → ATTENSE)"],
)

_translator = HiveEventTranslator()


def _annotate_investigation_gap(event, store, incident_id: str) -> None:
    """
    Flag a containment_initiated event that fired with little or no prior
    investigation on this incident. Scoring-only — never blocks the action;
    the analyst already triggered the responder in TheHive by the time this
    webhook arrives.
    """
    investigation_events = [
        e for e in store.get_events(incident_id)
        if e.event_type == "alert_investigation_started" and e.timestamp <= event.timestamp
    ]
    if event.metadata is None:
        event.metadata = {}
    if not investigation_events:
        event.metadata["investigation_skipped"] = True
        logger.info(
            "[Webhook] Containment fired for incident '%s' with no prior investigation event",
            incident_id,
        )
        return
    last_investigation = max(investigation_events, key=lambda e: e.timestamp)
    gap_seconds = (event.timestamp - last_investigation.timestamp).total_seconds()
    event.metadata["investigation_gap_seconds"] = round(gap_seconds, 1)
    event.metadata["premature_containment"] = gap_seconds < CONTAINMENT_INVESTIGATION_MIN_SECONDS
    logger.info(
        "[Webhook] Containment gap for incident '%s': %.1fs since investigation started (premature=%s)",
        incident_id, gap_seconds, event.metadata["premature_containment"],
    )


@webhook_router.post(
    "/hive",
    status_code=status.HTTP_200_OK,
    summary="[Internal] Receive a webhook event from TheHive",
)
async def receive_hive_webhook(
    request: Request,
    emitter: EventEmitter = Depends(get_event_emitter),
    attacher: AttackerLogAttacher = Depends(get_attacker_log_attacher),
    settings: Settings = Depends(get_settings),
) -> dict:
    """
    Internal endpoint called by TheHive when an analyst performs an action.

    TheHive must be configured with a notifier pointing at:
        http://localhost:8010/internal/webhook/hive

    Steps:
    1. Parse the Hive payload.
    2. Extract the ATTENSE incident_id from case tags / custom fields.
    3. Translate the Hive event into an ATTENSE Event via HiveEventTranslator.
    4. Look up the existing (Incident, EventStore) pair.
    5. Emit the translated event into the ATTENSE event store.
    """
    # ── Authenticate: the request must carry TheHive's shared bearer secret ──
    # TheHive is configured (thehive/application.conf → webhook `auth`) to send
    # `Authorization: Bearer <WEBHOOK_SECRET>` on every webhook. Reject anything
    # else so no other caller can inject analyst actions / state transitions.
    # Constant-time compare to avoid leaking the secret via timing.
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token.encode("utf-8"), settings.webhook_secret.encode("utf-8")
    ):
        logger.warning("[Webhook] Rejected webhook: missing/invalid bearer token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_webhook_token",
        )

    try:
        payload = await request.json()
    except Exception as exc:
        logger.warning("[Webhook] Failed to parse Hive payload: %s", exc)
        return {"status": "error", "reason": "invalid_json"}

    object_type = payload.get("objectType", "?")
    operation   = payload.get("operation", "?")
    logger.debug("[Webhook] Received Hive event: %s/%s", object_type, operation)

    # Step 1: Resolve the ATTENSE incident_id from the Hive payload
    incident_id = _translator.extract_incident_id(payload)
    if incident_id is None:
        logger.debug(
            "[Webhook] No ATTENSE incident_id found in %s/%s payload — ignoring",
            object_type, operation,
        )
        return {"status": "ignored", "reason": "no_incident_id"}

    # Step 2: Translate to ATTENSE Event
    event = _translator.translate(payload, incident_id)
    if event is None:
        return {"status": "ignored", "reason": "no_mapping"}

    # Step 3: Get or create the incident.
    # TheHive is the source of truth for analyst actions. If the incident
    # doesn't exist yet in memory (e.g. container was restarted), we
    # create it on-the-fly so events are never silently dropped.
    incident, store = emitter.get_or_create(incident_id, scenario_id="hive")

    # Safety: destructive / side-effecting actions (blocking IPs, disabling
    # services, isolation, etc.) MUST be explicitly confirmed by an analyst
    # in the Hive payload. This prevents automatic coordinators or other
    # automated callers from triggering real-world side effects.
    SIDE_EFFECTING_EVENTS = {
        "containment_initiated",
        "block_ip",
        "disable_service",
        "isolate_host",
        "responder_action",
    }

    if getattr(event, "event_type", None) in SIDE_EFFECTING_EVENTS:
        manual_ok = (
            payload.get("manual_confirm") is True
            or payload.get("manual") is True
            or str(payload.get("updatedBy", "")).lower().startswith("manual")
        )
        if not manual_ok:
            logger.warning(
                "[Webhook] Ignoring side-effecting action %s from non-manual source",
                event.event_type,
            )
            return {"status": "ignored", "reason": "manual_confirmation_required"}

    # Score whether the analyst investigated before containing: compare this
    # containment action's timestamp against the most recent
    # alert_investigation_started event already recorded for this incident.
    if event.event_type == "containment_initiated":
        _annotate_investigation_gap(event, store, incident_id)

    # Step 4: Emit — persists the event and updates incident state
    try:
        emitter.emit(incident, store, event)
    except Exception as exc:
        logger.error("[Webhook] Failed to emit translated event: %s", exc)
        return {"status": "error", "reason": str(exc)}

    logger.info(
        "[Webhook] Hive %s/%s → ATTENSE '%s' emitted for incident '%s'",
        object_type, operation, event.event_type, incident_id,
    )

    # Step 5: On case creation (alert promoted to a case), attach the attacker's
    # activity log + IOCs to the new case. Read-only enrichment — attach-once,
    # never breaks the webhook. TheHive 4.1.x sends lowercase objectType/operation
    # ('case'/'create').
    if object_type.strip().lower() == "case" and operation.strip().lower() == "create":
        object_data = payload.get("object", {})
        case_id = object_data.get("id") or object_data.get("_id") or payload.get("objectId")
        attacher.attach(case_id, incident)

    return {
        "status": "translated",
        "attense_event_type": event.event_type,
        "event_id": event.event_id,
        "incident_id": incident_id,
    }
