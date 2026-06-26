"""
hive_event_translator.py — Hive Webhook → ATTENSE Event Translator
===================================================================
Receives raw TheHive webhook payloads and maps them to ATTENSE events.

The translator maps Hive UI actions to the real ATTENSE lifecycle events.
These events go through the same emitter as API-driven events, which means
they advance the incident state machine exactly as if the analyst had called
the BlueTeam REST API directly.

Mapping logic:
    Case / Create           → alert_investigation_started  (analyst opened a case)
    Case / Update (Resolved)→ incident_ended               (analyst closed the case)
    Case / Update (other)   → incident_confirmed           (analyst updated → confirmed)
    Alert / Update          → alert_raised                 (alert was updated in Hive)
    Task / Update (Completed)→ containment_succeeded       (task completed = contained)
    Task / Update (Cancelled)→ containment_failed          (task cancelled = failed)
    Task / Update (other)   → containment_initiated        (task started = initiating)

All other Hive event types are silently ignored (returns None).

Convention for linking Hive cases to ATTENSE incidents:
    Hive cases are tagged with 'attense:incident-<incident_id>'
    Example: 'attense:incident-inc-abc123'
    This tag is set by BlueTeam when it calls HiveClient.create_case().
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import Optional

from ATTENSE_app.events.event import Event
from blueteam.core.blueactions.hive_keywords import (
    DISMISSAL_APPROVED_RE as _DISMISSAL_APPROVED_RE,
    LESSONS_LEARNED_RE   as _LESSONS_LEARNED_RE,
)

logger = logging.getLogger(__name__)


def _new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


class HiveEventTranslator:
    """
    Translates a raw Hive webhook payload into an ATTENSE Event object.

    All mapped event types and target types are validated against
    ATTENSE's allowed sets — no custom Hive-only event types are used.

    Usage
    -----
    translator = HiveEventTranslator()
    event = translator.translate(payload, incident_id)
    if event:
        emitter.emit(incident, store, event)
    """

    def translate(self, payload: dict, incident_id: str) -> Optional[Event]:
        """
        Translate a Hive webhook payload into an ATTENSE Event.

        Parameters
        ----------
        payload     : Raw JSON dict received from TheHive webhook.
        incident_id : ATTENSE incident_id resolved from the Hive case tags.

        Returns
        -------
        Event  — if a mapping exists for the Hive objectType/operation.
        None   — if this webhook type has no ATTENSE mapping (silently ignored).
        """
        object_type = payload.get("objectType", "")
        operation   = payload.get("operation", "")
        object_data = payload.get("object", {})
        hive_status = object_data.get("status", "")

        attense_event_type, target_type, outcome = self._resolve_mapping(
            object_type, operation, payload
        )

        if attense_event_type is None:
            logger.debug(
                "[HiveTranslator] No mapping for %s/%s (status=%r) — skipping",
                object_type, operation, hive_status,
            )
            return None

        meta = {
            "hive_object_type": object_type,
            "hive_operation":   operation,
            "hive_object_id":   object_data.get("id") or object_data.get("_id"),
            "hive_title":       object_data.get("title"),
            "hive_severity":    object_data.get("severity"),
            "hive_status":      hive_status or None,
            "source":           "hive_webhook",
        }
        # Remove None values to keep metadata clean
        meta = {k: v for k, v in meta.items() if v is not None}
        
        # Extract the analyst username (from updatedBy or createdBy)
        analyst_username = payload.get("updatedBy") or payload.get("createdBy") or "thehive"

        event = Event(
            event_id=_new_event_id(),
            incident_id=incident_id,
            scenario_id="hive",          # webhook events are not scenario-bound
            actor_id=analyst_username,
            target_id=object_data.get("id") or object_data.get("_id") or "unknown",
            event_type=attense_event_type,
            actor_type="blue_team",
            target_type=target_type,
            timestamp=datetime.now(),
            outcome=outcome,
            metadata=meta,
        )

        logger.info(
            "[HiveTranslator] %s/%s (status=%r) → %s (incident: %s)",
            object_type, operation, hive_status, attense_event_type, incident_id,
        )
        return event

    @staticmethod
    def _resolve_mapping(
        object_type: str, operation: str, payload: dict
    ) -> tuple[Optional[str], str, str]:
        """
        Map a (objectType, operation, payload) triple to an ATTENSE
        (event_type, target_type, outcome) triple.
        """
        object_data = payload.get("object", {})
        details = payload.get("details", {})
        hive_status = object_data.get("status", "")
        resolution = object_data.get("resolutionStatus", "")

        # TheHive 4.1.x webhook vocabulary is lowercase and uses internal type
        # names (e.g. objectType='case', operation='create', 'case_task',
        # 'case_task_log'). Normalise to canonical tokens so the mappings below
        # are robust to casing/naming. Status field values (Open/Resolved/…)
        # stay as-is — those are domain values, not the webhook envelope.
        otype = {
            "case": "case", "alert": "alert",
            "case_task": "task", "task": "task",
            "case_task_log": "tasklog", "tasklog": "tasklog",
            "action": "responderaction", "responderaction": "responderaction",
        }.get(object_type.strip().lower(), object_type.strip().lower())
        op = operation.strip().lower()  # create | update | delete

        # 1. alert_investigation_started
        if otype == "alert" and op == "update":
            # If the owner field was changed/set in this update
            if "owner" in details:
                return "alert_investigation_started", "alert", "unknown"

        # 2. alert_denied
        if otype == "alert" and op == "update":
            if hive_status == "Ignored":
                return "alert_denied", "alert", "false_positive"

        # 3. incident_confirmed
        if otype == "case" and op == "create":
            return "incident_confirmed", "alert", "detected"
        if otype == "alert" and op == "update" and hive_status == "Imported":
            return "incident_confirmed", "alert", "detected"

        # 4. containment_initiated
        if otype == "task" and op == "update" and hive_status in ("InProgress", "Waiting"):
            return "containment_initiated", "host", "unknown"
        if otype == "responderaction" and op == "create":
            return "containment_initiated", "host", "unknown"

        # 5. containment_succeeded / containment_failed — Cortex reports back via ResponderAction/Update
        # When Cortex finishes running WazuhBlockIP it updates the ResponderAction with its final status.
        # TheHive emits a webhook for this update — we map it here so the incident can reach CONTAINED.
        if otype == "responderaction" and op == "update":
            responder_status = object_data.get("status", "")
            if responder_status == "Success":
                return "containment_succeeded", "host", "success"
            if responder_status in ("Failure", "Timeout"):
                return "containment_failed", "host", "failure"
            # Any other intermediate state (e.g. "InProgress") → ignore
            return None, "host", "unknown"

        # 5b. containment_succeeded via Task completion (manual task path — no Cortex)
        #     BUT: if the completed task title matches lessons-learned keywords, that
        #     takes priority — a "Lessons Learned" task completing is not containment.
        if otype == "task" and op == "update" and hive_status == "Completed":
            title = object_data.get("title", "") or object_data.get("description", "") or ""
            if _LESSONS_LEARNED_RE.search(title):
                return "lessons_learned_recorded", "alert", "success"
            return "containment_succeeded", "host", "success"

        if otype == "tasklog" and op == "create":
            message = object_data.get("message", "") or ""

            # 6a. dismissal_approved — keyword match takes highest priority.
            #     The second-actor guard (self-approval prevention) is enforced by
            #     the webhook router AFTER translation, not here.
            if _DISMISSAL_APPROVED_RE.search(message):
                return "dismissal_approved", "alert", "success"

            # 6b. lessons_learned_recorded — keyword match
            if _LESSONS_LEARNED_RE.search(message):
                return "lessons_learned_recorded", "alert", "success"

            # 6c. containment_failed / containment_succeeded — generic fallback
            message_lower = message.lower()
            if "failed" in message_lower or "error" in message_lower:
                return "containment_failed", "host", "failure"

            if hive_status == "Completed":
                return "containment_succeeded", "host", "success"

        # 7. incident_ended
        if otype == "case" and op == "update":
            if hive_status in ("Resolved", "Closed"):
                if resolution == "FalsePositive":
                    return "alert_denied", "alert", "false_positive"
                if resolution == "Duplicated":
                    return "alert_denied", "alert", "allowed"
                if resolution == "TruePositive":
                    return "incident_ended", "alert", "success"
                return "incident_ended", "alert", "unknown"

        # Fallback for unexpected mapping
        return None, "alert", "unknown"

    @staticmethod
    def extract_incident_id(payload: dict) -> Optional[str]:
        """
        Extract the ATTENSE incident_id from a Hive webhook payload.

        Looks in:
          1. Case tags:          'attense:incident-<id>'
          2. Custom fields:      customFields.attenseIncidentId.string
          3. Description prefix: 'Automated case for incident <id>'

        Returns None if no incident_id can be found.
        """
        object_data = payload.get("object", {})

        # 1. Tags: 'attense:incident-inc-abc123'
        for tag in object_data.get("tags", []):
            if isinstance(tag, str) and tag.startswith("attense:incident-"):
                return tag.replace("attense:incident-", "", 1)

        # 2. Custom fields
        custom = object_data.get("customFields", {})
        cf_val = custom.get("attenseIncidentId", {})
        if isinstance(cf_val, dict) and cf_val.get("string"):
            return cf_val["string"]

        # 3. Description fallback
        desc = object_data.get("description", "")
        if desc.startswith("Automated case for incident "):
            return desc.replace("Automated case for incident ", "", 1).strip()

        return None
