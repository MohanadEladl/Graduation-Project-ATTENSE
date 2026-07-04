"""
hive_event_translator.py — Hive Webhook → ATTENSE Event Translator
===================================================================
Receives raw TheHive webhook payloads and maps them to ATTENSE events
by calling the appropriate blueaction event builders.

This is the adapter layer that sits ABOVE the pure blueaction builders.
The builders already know how to construct Events from ATTENSE-native
inputs. This translator knows how to extract those inputs from a
Hive-shaped webhook payload.

Supported Hive object types and operations:
    Case / Update       → hive_case_updated    (metadata event, no state change)
    Case / Delete       → hive_case_closed     (metadata event)
    Alert / Update      → hive_alert_updated   (metadata event)
    Observable / Create → hive_observable_added (metadata event)

These are informational ATTENSE events — they do NOT replace the
analyst workflow events (raise_alert, confirm_incident, etc.).
Those still come in through the BlueTeam API from ATTENSE Core.

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

logger = logging.getLogger(__name__)

# Maps (Hive objectType, operation) → ATTENSE event_type string
HIVE_EVENT_MAP: dict[tuple[str, str], str] = {
    ("Case",       "Create"):  "alert_investigation_started",
    ("Case",       "Update"):  "hive_case_updated",
    ("Case",       "Delete"):  "hive_case_closed",
    ("Alert",      "Update"):  "hive_alert_updated",
    ("Observable", "Create"):  "hive_observable_added",
    ("Task",       "Update"):  "hive_task_updated",
}


def _new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


class HiveEventTranslator:
    """
    Translates a raw Hive webhook payload into an ATTENSE Event object.

    Usage
    -----
    translator = HiveEventTranslator()
    event = translator.translate(payload)
    if event:
        emitter.emit(incident, store, event)
    """

    def translate(self, payload: dict, incident_id: str) -> Optional[Event]:
        """
        Attempt to translate a Hive webhook payload into an ATTENSE Event.

        Parameters
        ----------
        payload     : Raw JSON dict received from TheHive webhook.
        incident_id : ATTENSE incident_id resolved from the Hive case tags.

        Returns
        -------
        Event  — if a mapping exists for the Hive objectType/operation.
        None   — if this webhook type has no ATTENSE mapping (caller ignores it).
        """
        object_type = payload.get("objectType", "")
        operation   = payload.get("operation", "")
        object_data = payload.get("object", {})

        attense_event_type = HIVE_EVENT_MAP.get((object_type, operation))
        if attense_event_type is None:
            logger.debug(
                "[HiveTranslator] No mapping for %s/%s — skipping",
                object_type, operation,
            )
            return None

        # Extract useful fields from the Hive object for metadata
        meta = {
            "hive_object_type": object_type,
            "hive_operation":   operation,
            "hive_object_id":   object_data.get("id") or object_data.get("_id"),
            "hive_title":       object_data.get("title"),
            "hive_severity":    object_data.get("severity"),
            "hive_status":      object_data.get("status"),
            "source":           "hive_webhook",
        }
        # Remove None values to keep metadata clean
        meta = {k: v for k, v in meta.items() if v is not None}

        event = Event(
            event_id=_new_event_id(),
            incident_id=incident_id,
            scenario_id="hive",           # webhook events are not scenario-bound
            actor_id="thehive",
            target_id=object_data.get("id") or object_data.get("_id") or "unknown",
            event_type=attense_event_type,
            actor_type="system",
            target_type=object_type.lower(),
            timestamp=datetime.now(),
            outcome="unknown",
            metadata=meta,
        )

        logger.info(
            "[HiveTranslator] %s/%s → %s (incident: %s)",
            object_type, operation, attense_event_type, incident_id,
        )
        return event

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
