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

from ..blueactions.alert_actions import (
    build_raise_alert_event,
    build_investigate_alert_event,
    build_deny_alert_event,
)
from ..validation.alert_validator import (
    validate_raise_alert,
    validate_investigate_alert,
    validate_deny_alert,
)
from ...infrastructure.eventstore.event_emitter import EventEmitter
from ...infrastructure.thehive.hive_client import HiveClient
from ...infrastructure.cortex.enrichment_service import EnrichmentReport
from ...schemas.requests.alert_requests import (
    RaiseAlertRequest,
    InvestigateAlertRequest,
    DenyAlertRequest,
)
from ...schemas.responses.action_response import ActionResponse

logger = logging.getLogger(__name__)


def raise_alert(
    body: RaiseAlertRequest,
    emitter: EventEmitter,
    hive: HiveClient,
    enrichment_report: EnrichmentReport,
    room_id: str,
    auto_create_case: bool = False,
) -> ActionResponse:
    """
    Simulate the SIEM detecting an anomaly and raising an alert, and forward it to TheHive.

    Called by: system / SIEM automation
    Pre-condition: incident not already CONTAINED or ENDED.
    Emits: alert_raised

    If *auto_create_case* is True, the new alert is immediately promoted to a
    case (alert → case). That fires TheHive's CaseCreated webhook, which makes
    the Blue Team backend auto-attach the attacker activity log — so an attack
    surfaces as a fully-populated case with no manual analyst step.
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
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

    # Convert Cortex-Lite enrichment report IOCs to TheHive artifacts format,
    # attaching the actual AbuseIPDB/VirusTotal findings to each observable so
    # the analyst sees real evidence in TheHive before choosing a response.
    artifacts = []
    for ip in enrichment_report.iocs_found.get("ips", []):
        message, tags = enrichment_report.describe(ip, "ip")
        artifacts.append({"dataType": "ip", "data": ip, "message": message, "tags": tags})
    for url in enrichment_report.iocs_found.get("urls", []):
        message, tags = enrichment_report.describe(url, "url")
        artifacts.append({"dataType": "url", "data": url, "message": message, "tags": tags})
    for h in enrichment_report.iocs_found.get("hashes", []):
        message, tags = enrichment_report.describe(h, "hash")
        artifacts.append({"dataType": "hash", "data": h, "message": message, "tags": tags})

    # Create the Alert in TheHive
    try:
        res = hive.create_alert(
            incident_id=incident.incident_id,
            title=body.rule_name or "SIEM Alert",
            severity=body.severity,
            artifacts=artifacts,
            enrichment_summary=enrichment_report.enrichment_note,
        )
        alert_id = res.get("id") or res.get("_id")
        if alert_id:
            logger.info(
                "[AlertService] Alert created in TheHive: alert_id=%s for incident '%s'.",
                alert_id, incident.incident_id,
            )
            # Auto-promote alert → case so the incident surfaces automatically
            # (the CaseCreated webhook then triggers attacker-log attachment).
            if auto_create_case:
                case = hive.promote_alert_to_case(alert_id)
                if case.get("id") or case.get("_id"):
                    logger.info(
                        "[AlertService] Alert %s auto-promoted to case %s (incident '%s').",
                        alert_id, case.get("id") or case.get("_id"), incident.incident_id,
                    )
                else:
                    logger.warning(
                        "[AlertService] Auto-promote of alert %s returned no case id: %s",
                        alert_id, case,
                    )
        else:
            logger.warning(
                "[AlertService] TheHive created alert but returned no ID: %s",
                res,
            )
    except Exception as exc:
        logger.warning(
            "[AlertService] TheHive alert creation/promotion failed (non-fatal): %s",
            exc,
        )

    logger.info(
        "[AlertService] Alert RAISED for incident '%s' — rule='%s', severity='%s'.",
        incident.incident_id, body.rule_name, body.severity,
    )
    return ActionResponse.from_event(incident, event,
        f"Alert raised by '{body.siem_id}' (rule={body.rule_name}, severity={body.severity}).")


def investigate_alert(body: InvestigateAlertRequest, emitter: EventEmitter, room_id: str) -> ActionResponse:
    """
    Analyst picks up an alert and starts investigation/triage.

    Called by: human analyst (via Hive or UI)
    Pre-condition: alert_raised event must already exist for this incident.
    Emits: alert_investigation_started
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
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


def deny_alert(body: DenyAlertRequest, emitter: EventEmitter, room_id: str) -> ActionResponse:
    """
    Analyst marks the alert as a false positive. Incident ends here — no TTD recorded.

    Called by: human analyst (via Hive or UI)
    Pre-condition: alert_investigation_started must already exist.
    Emits: alert_denied
    """
    incident, store = emitter.get_or_create(room_id, body.incident_id, body.scenario_id)
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
