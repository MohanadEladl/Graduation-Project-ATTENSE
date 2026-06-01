"""
alert_service.py — Alert Service (Blue Team Core)
===================================================
Handles all alert-related analyst actions:
    raise_alert()        → system/SIEM raises an alert (EVENT: alert_raised)
    investigate_alert()  → analyst starts triage     (EVENT: alert_investigation_started)
    deny_alert()         → analyst marks false +ve   (EVENT: alert_denied)

Each function:
    1. Delegates validation to core/validation/alert_validator.py
    2. Delegates event building to core/blueactions/alert_actions.py
    3. Persists the event via the EventEmitter
    4. Returns an ActionResponse
"""

from __future__ import annotations

import logging

from core.blueactions.alert_actions import (
    build_raise_alert_event,
    build_investigate_alert_event,
    build_deny_alert_event,
)
from core.validation.alert_validator import (
    validate_raise_alert,
    validate_investigate_alert,
    validate_deny_alert,
)
from infrastructure.eventstore.event_emitter import EventEmitter
from infrastructure.thehive.hive_client import HiveClient
from infrastructure.cortex.enrichment_service import EnrichmentReport
from schemas.requests.alert_requests import (
    RaiseAlertRequest,
    InvestigateAlertRequest,
    DenyAlertRequest,
)
from schemas.responses.action_response import ActionResponse

logger = logging.getLogger(__name__)


def raise_alert(
    body: RaiseAlertRequest,
    emitter: EventEmitter,
    hive: HiveClient,
    enrichment_report: EnrichmentReport,
) -> ActionResponse:
    """
    Simulate the SIEM detecting an anomaly and raising an alert, and forward it to TheHive.

    Called by: system / SIEM automation
    Pre-condition: incident not already CONTAINED or ENDED.
    Emits: alert_raised
    """
    incident, store = emitter.get_or_create(body.incident_id, body.scenario_id)
    validate_raise_alert(incident, store)

    event = build_raise_alert_event(
        incident=incident,
        siem_id=body.siem_id,
        target_id=body.target_id,
        target_type=body.target_type,
        rule_name=body.rule_name,
        severity=body.severity,
        raw_log=body.raw_log,
    )
    emitter.emit(incident, store, event)

    # Convert Cortex-Lite enrichment report IOCs to TheHive artifacts format
    artifacts = []
    for ip in enrichment_report.iocs_found.get("ips", []):
        artifacts.append({"dataType": "ip", "data": ip, "message": "Attacker IP"})
    for url in enrichment_report.iocs_found.get("urls", []):
        artifacts.append({"dataType": "url", "data": url, "message": "Malicious URL"})
    for h in enrichment_report.iocs_found.get("hashes", []):
        artifacts.append({"dataType": "hash", "data": h, "message": "Malicious File Hash"})

    # Create the Alert in TheHive
    try:
        res = hive.create_alert(
            incident_id=incident.incident_id,
            title=body.rule_name or "SIEM Alert",
            severity=body.severity,
            artifacts=artifacts,
        )
        alert_id = res.get("id") or res.get("_id")
        if alert_id:
            logger.info(
                "[AlertService] Alert created in TheHive: alert_id=%s for incident '%s'.",
                alert_id, incident.incident_id,
            )
        else:
            logger.warning(
                "[AlertService] TheHive created alert but returned no ID: %s",
                res,
            )
    except Exception as exc:
        logger.warning(
            "[AlertService] TheHive alert creation failed (non-fatal): %s",
            exc,
        )

    logger.info(
        "[AlertService] Alert RAISED for incident '%s' — rule='%s', severity='%s'.",
        incident.incident_id, body.rule_name, body.severity,
    )
    return ActionResponse.from_event(incident, event,
        f"Alert raised by '{body.siem_id}' (rule={body.rule_name}, severity={body.severity}).")


def investigate_alert(body: InvestigateAlertRequest, emitter: EventEmitter) -> ActionResponse:
    """
    Analyst picks up an alert and starts investigation/triage.

    Called by: human analyst (via Hive or UI)
    Pre-condition: alert_raised event must already exist for this incident.
    Emits: alert_investigation_started
    """
    incident, store = emitter.get_or_create(body.incident_id, body.scenario_id)
    validate_investigate_alert(incident, store)

    event = build_investigate_alert_event(
        incident=incident,
        analyst_id=body.analyst_id,
        alert_id=body.alert_id,
        notes=body.notes,
    )
    emitter.emit(incident, store, event)

    logger.info(
        "[AlertService] Analyst '%s' INVESTIGATING alert '%s' for incident '%s'.",
        body.analyst_id, body.alert_id, incident.incident_id,
    )
    return ActionResponse.from_event(incident, event,
        f"Alert '{body.alert_id}' is now under investigation by '{body.analyst_id}'.")


def deny_alert(body: DenyAlertRequest, emitter: EventEmitter) -> ActionResponse:
    """
    Analyst marks the alert as a false positive. Incident ends here — no TTD recorded.

    Called by: human analyst (via Hive or UI)
    Pre-condition: alert_investigation_started must already exist.
    Emits: alert_denied
    """
    incident, store = emitter.get_or_create(body.incident_id, body.scenario_id)
    validate_deny_alert(incident, store)

    event = build_deny_alert_event(
        incident=incident,
        analyst_id=body.analyst_id,
        alert_id=body.alert_id,
        notes=body.notes,
    )
    emitter.emit(incident, store, event)

    logger.info(
        "[AlertService] Analyst '%s' DENIED alert '%s' as FALSE POSITIVE for incident '%s'.",
        body.analyst_id, body.alert_id, incident.incident_id,
    )
    return ActionResponse.from_event(incident, event,
        f"Alert '{body.alert_id}' marked as false positive by '{body.analyst_id}'.")
