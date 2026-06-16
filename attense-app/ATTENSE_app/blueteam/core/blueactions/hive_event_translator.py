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
import uuid
from datetime import datetime
from typing import Optional

from ATTENSE_app.events.event import Event
from core.blueactions.analyst_action_extractor import extract_analyst_action
from routers.analyst_actions import store_analyst_action

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

    def __init__(self) -> None:
        # Cache: TheHive case _id  → ATTENSE incident_id
        # Populated when case events with attense:incident-* tags arrive.
        # Used to resolve incident_id for child task/log events that carry
        # no case tags — only a reference back to the parent case ID.
        self._case_incident_map: dict[str, str] = {}

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
        # TheHive 4.1.24 CE sends lowercase objectType/operation ("case", "create").
        # Normalise to lowercase here; all comparisons below use lowercase.
        object_type = payload.get("objectType", "").lower()
        operation   = payload.get("operation",   "").lower()
        object_data = payload.get("object", {})
        hive_status = object_data.get("status", "")

        # Analyst action extraction — independent of the ATTENSE event
        # translation below. Runs even for Hive events that don't map to
        # an ATTENSE incident-state event, since it writes to the separate
        # analyst-action scoring store used by the Watcher Agent endpoints.
        # Pass incident_id explicitly so task events (which carry no case tags)
        # can still be scored correctly.
        try:
            action = extract_analyst_action(payload, incident_id=incident_id)
            if action:
                store_analyst_action(action)
                logger.info(
                    "[HiveTranslator] analyst action recorded: %s → %s",
                    action["analyst_id"], action["event_type"],
                )
        except Exception as exc:
            logger.warning("[HiveTranslator] Analyst action extraction failed: %s", exc)

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

        object_type and operation are expected already normalised to lowercase
        by the caller (TheHive 4.1.24 CE sends lowercase; earlier versions may
        send title case — normalising at the top of translate() handles both).
        """
        object_data = payload.get("object", {})
        details = payload.get("details", {})
        hive_status = object_data.get("status", "")
        resolution = object_data.get("resolutionStatus", "")

        # 1. alert_investigation_started
        if object_type == "alert" and operation == "update":
            if "owner" in details:
                return "alert_investigation_started", "alert", "unknown"

        # 2. alert_denied
        if object_type == "alert" and operation == "update":
            if hive_status == "Ignored":
                return "alert_denied", "alert", "false_positive"

        # 3. incident_confirmed
        if object_type == "case" and operation == "create":
            return "incident_confirmed", "alert", "detected"
        if object_type == "alert" and operation == "update" and hive_status == "Imported":
            return "incident_confirmed", "alert", "detected"

        # 4. containment_initiated
        if object_type == "task" and operation == "update" and hive_status in ("InProgress", "Waiting"):
            return "containment_initiated", "host", "unknown"
        if object_type == "responderaction" and operation == "create":
            return "containment_initiated", "host", "unknown"

        # 5. containment_succeeded / containment_failed — Cortex reports back via ResponderAction/Update
        if object_type == "responderaction" and operation == "update":
            responder_status = object_data.get("status", "")
            if responder_status == "Success":
                return "containment_succeeded", "host", "success"
            if responder_status in ("Failure", "Timeout"):
                return "containment_failed", "host", "failure"
            return None, "host", "unknown"

        # 5b. containment_succeeded via Task completion (manual task path — no Cortex)
        if object_type == "task" and operation == "update" and hive_status == "Completed":
            return "containment_succeeded", "host", "success"
        if object_type == "tasklog" and operation == "create":
            message = object_data.get("message", "").lower()
            if "failed" in message or "error" in message:
                return "containment_failed", "host", "failure"
            if hive_status == "Completed":
                return "containment_succeeded", "host", "success"

        # 7. incident_ended
        if object_type == "case" and operation == "update":
            if hive_status in ("Resolved", "Closed"):
                if resolution == "FalsePositive":
                    return "alert_denied", "alert", "false_positive"
                if resolution == "Duplicated":
                    return "alert_denied", "alert", "allowed"
                if resolution == "TruePositive":
                    return "incident_ended", "alert", "success"
                return "incident_ended", "alert", "unknown"

        return None, "alert", "unknown"

    def extract_incident_id(self, payload: dict) -> Optional[str]:
        """
        Extract the ATTENSE incident_id from a Hive webhook payload.

        Lookup order:
          1. Case tags:          'attense:incident-<id>'  (case events)
          2. Custom fields:      customFields.attenseIncidentId.string
          3. Description prefix: 'Automated case for incident <id>'
          4. Case→incident cache: task/log events carry a 'case' field or
             a top-level 'rootId' pointing back to the parent case; look up
             that case_id in the cache populated by prior case events.

        When an incident_id is resolved via tags/fields, the case_id→incident_id
        mapping is registered in self._case_incident_map so that child task events
        can find it without carrying case tags themselves.
        """
        object_data = payload.get("object", {})

        # 1. Tags: 'attense:incident-inc-abc123'
        for tag in object_data.get("tags", []):
            if isinstance(tag, str) and tag.startswith("attense:incident-"):
                incident_id = tag.replace("attense:incident-", "", 1)
                # Register so child task events can find this incident
                case_id = object_data.get("_id") or object_data.get("id")
                if case_id:
                    self._case_incident_map[case_id] = incident_id
                return incident_id

        # 2. Custom fields
        custom = object_data.get("customFields", {})
        cf_val = custom.get("attenseIncidentId", {})
        if isinstance(cf_val, dict) and cf_val.get("string"):
            incident_id = cf_val["string"]
            case_id = object_data.get("_id") or object_data.get("id")
            if case_id:
                self._case_incident_map[case_id] = incident_id
            return incident_id

        # 3. Description fallback
        desc = object_data.get("description", "")
        if desc.startswith("Automated case for incident "):
            incident_id = desc.replace("Automated case for incident ", "", 1).strip()
            case_id = object_data.get("_id") or object_data.get("id")
            if case_id:
                self._case_incident_map[case_id] = incident_id
            return incident_id

        # 4. Task / log events: the object has no case tags, but carries a
        #    'case' field (parent case _id) or the payload has a top-level
        #    'rootId'.  Look both up in the cache.
        #    Either field may be a plain string ID or a nested dict — drill
        #    down until we get a hashable string.
        def _to_id(v: object) -> str | None:
            if isinstance(v, str):
                return v or None
            if isinstance(v, dict):
                return v.get("_id") or v.get("id") or None
            return None

        parent_case = (
            _to_id(object_data.get("case"))
            or _to_id(payload.get("rootId"))
        )
        if parent_case and parent_case in self._case_incident_map:
            return self._case_incident_map[parent_case]

        return None
