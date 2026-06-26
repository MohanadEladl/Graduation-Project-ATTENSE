"""
analyst_action_extractor.py
Extracts a scored analyst action from a TheHive webhook payload.
Returns None if the event doesn't map to a meaningful SOC action.

This sits alongside hive_event_translator.py — it does NOT replace it.
The translator maps Hive events into ATTENSE incident-state events;
this extractor maps the same payload into analyst-action records for
the /blueteam/analyst-action scoring store.
"""

from __future__ import annotations

import re

from blueteam.core.blueactions.hive_keywords import (
    DISMISSAL_APPROVED_RE as _DISMISSAL_APPROVED_RE,
    LESSONS_LEARNED_RE   as _LESSONS_LEARNED_RE,
)

# Maps (objectType, operation, optional_status) → AnalystEventType
# object_type and operation are matched in lowercase (normalised on entry).
# optional_status is matched case-insensitively against a combined string of
# obj["status"] + " " + obj["resolutionStatus"] so resolution-specific rules
# can fire before generic resolved rules.
# TheHive 4.1.24 CE objectTypes: "case", "alert", "case_task",
#   "case_task_log", "responderaction" — all lowercase.
# Order matters — first match wins.
_RULES = [
    # Analyst opens/starts working a case
    ("case",       "create",  None,              "investigation_started"),
    # Analyst confirms incident by moving case to Open
    ("case",       "update",  "Open",            "incident_confirmed"),
    # Containment task started (task created with InProgress OR updated to InProgress)
    ("case_task",  "create",  "InProgress",      "containment_initiated"),
    ("case_task",  "update",  "InProgress",      "containment_initiated"),
    # Task completed → containment succeeded
    ("case_task",  "update",  "Completed",       "containment_succeeded"),
    # Case closed as true positive → incident ended (check before generic Resolved)
    ("case",       "update",  "TruePositive",    "incident_ended"),
    # Case resolved any other way → containment succeeded
    ("case",       "update",  "Resolved",        "containment_succeeded"),
    # Case or alert dismissed / false positive
    ("case",       "update",  "FalsePositive",   "alert_denied"),
    ("alert",      "update",  "Ignored",         "alert_denied"),
    ("alert",      "update",  "FalsePositive",   "alert_denied"),
]


def extract_analyst_action(
    payload: dict,
    incident_id: str | None = None,
) -> dict | None:
    """
    Given a raw TheHive webhook payload, return an analyst action dict
    ready to pass to store_analyst_action(), or None if not applicable.

    incident_id may be passed explicitly by HiveEventTranslator (which has
    already resolved it, including from the case→incident cache) so that
    task events — which carry no case tags — can still be scored.
    """
    # Normalise: TheHive 4.1.24 CE sends lowercase ("case", "create").
    object_type = payload.get("objectType", "").lower()
    operation   = payload.get("operation",   "").lower()
    obj = payload.get("object", {})

    # Combined status string for rule matching: "Resolved TruePositive" etc.
    # Lets resolution-specific rules (TruePositive) fire before generic ones (Resolved).
    status_raw   = obj.get("status")           or obj.get("stage")            or ""
    resolution   = obj.get("resolutionStatus") or obj.get("impactStatus")     or ""
    status = f"{status_raw} {resolution}".strip()

    # Match against rules
    action_type = None
    for rule_type, rule_op, rule_status, mapped in _RULES:
        if rule_type != object_type:
            continue
        if rule_op != operation:
            continue
        if rule_status and rule_status.lower() not in status.lower():
            continue
        action_type = mapped
        break

    # Keyword-based fallback for v2.0.0 events that cannot be matched by
    # (object_type, operation, status) alone — they're identified by message content.
    if not action_type:
        if object_type in ("case_task_log", "tasklog") and operation == "create":
            message = obj.get("message", "") or obj.get("description", "") or ""
            if _DISMISSAL_APPROVED_RE.search(message):
                action_type = "dismissal_approved"
            elif _LESSONS_LEARNED_RE.search(message):
                action_type = "lessons_learned_recorded"
        elif object_type in ("case_task", "task") and operation == "update":
            title = obj.get("title", "") or obj.get("description", "") or ""
            if (obj.get("status") or "").lower() == "completed" and _LESSONS_LEARNED_RE.search(title):
                action_type = "lessons_learned_recorded"

    if not action_type:
        return None

    # Extract analyst identity.
    # TheHive 4.1.24 CE sends camelCase fields (createdBy / updatedBy) at both
    # the top payload level and inside the object.  Earlier versions used the
    # _prefixed form; check both to be safe.
    raw_user = (
        payload.get("updatedBy")
        or payload.get("createdBy")
        or payload.get("_createdBy")
        or obj.get("updatedBy")
        or obj.get("createdBy")
        or obj.get("_updatedBy")
        or obj.get("_createdBy")
        or "analyst-unknown"
    )

    analyst_id = _slugify(raw_user)

    # Resolve incident_id: prefer the explicitly-passed value (from the caller's
    # case→incident cache), then fall back to tag extraction from the object.
    if not incident_id:
        incident_id = _extract_incident_id(obj)
    if not incident_id:
        return None  # can't score an action with no incident

    return {
        "analyst_id": analyst_id,
        "incident_id": incident_id,
        "scenario_id": _extract_scenario_id(obj),
        "event_type": action_type,
        "t_offset_sec": 0,
        "detail": _build_detail(object_type, operation, status, obj),
    }


def _slugify(raw: str) -> str:
    """'ahmed@lab.local' → 'analyst-ahmed'"""
    name = raw.split("@")[0]
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return f"analyst-{slug}"


def _extract_incident_id(obj: dict) -> str | None:
    tags = obj.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("attense:incident-"):
            return tag.replace("attense:incident-", "", 1)
    cf = obj.get("customFields", {})
    return cf.get("attenseIncidentId", {}).get("string")


def _extract_scenario_id(obj: dict) -> str:
    tags = obj.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("APP-"):
            return tag[:6]  # e.g. APP-01
    return "APP-00"


def _build_detail(object_type: str, operation: str, status: str, obj: dict) -> str:
    title = obj.get("title") or obj.get("description") or ""
    if title:
        return f"{object_type} {operation.lower()}: {title[:80]}"
    return f"{object_type} {operation.lower()} ({status})"
