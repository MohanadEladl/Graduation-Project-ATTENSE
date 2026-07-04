"""
mapper.py – Signal Mapper: Detection Adapter Layer
====================================================

Purpose
-------
Convert a raw Wazuh alert dict into a single ATTENSE Event and deliver
it to the incident state machine.

Design Contract  (do not violate this)
---------------------------------------
The Signal Mapper has exactly ONE job: translate a Wazuh detection
signal into a StandardEvent. Nothing more.

  ✅ It DOES:  parse Wazuh alerts
  ✅ It DOES:  classify the detection label  (xss, command_injection …)
  ✅ It DOES:  emit  'alert_raised'  — the only honest event type here
  ✅ It DOES:  preserve all telemetry in metadata for downstream use

  ❌ It does NOT emit 'malicious_action_executed'  — that is the attacker
  ❌ It does NOT infer or fabricate attacker behaviour
  ❌ It does NOT model lifecycle state
  ❌ It does NOT own or generate incident IDs

Why ONLY 'alert_raised'  (all phases)
---------------------------------------
Wazuh is a detection tool. It reads log files after something happened
and fires a rule when a pattern matches. That is a detection signal —
not proof that an attack executed, and certainly not the attack itself.

  malicious_action_executed → emitted by the ATTACKER NODE  (Phase 3+)
  alert_raised              → emitted by WAZUH via this mapper  ✅

This is correct across every phase:

  Phase 2  — only Wazuh exists → mapper emits alert_raised
             state machine uses it as both start_time and detection_time
             TTD = 0  (honest — the gap is not yet observable)

  Phase 3  — attacker node emits malicious_action_executed first
             mapper emits alert_raised after
             state machine now has both → TTD is real and meaningful

  Phase 4  — same as Phase 3, plus blue team events follow

The state machine — NOT the mapper — is responsible for handling
partial event streams. See incident.py for the fallback anchor logic.

Why incident_id is strict
--------------------------
INCIDENT_ID must be set in the environment before the mapper runs.
A missing value means the environment is misconfigured. We fail fast
here so the error surfaces immediately, not silently buried in a
corrupted timeline later.

Scenario coverage
-----------------
  APP-01  Cross-Site Scripting (XSS)
  APP-02  Command Injection
  APP-03  Directory Traversal
  APP-04  File Upload Exploit
  APP-05  Cross-Site Request Forgery (CSRF)
  APP-06  Broken Authentication
  APP-00  Generic / unclassified  (fallback)

⚠️  Caller contract
--------------------
map_alert() returns Optional[Event].
The caller must handle None (malformed / unclassifiable alert):

    event = map_alert(raw)
    if event is None:
        return
    dispatch(event)
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from app.classifier import classify
from app.parser import parse_alert
from app.schema import WazuhAlert
from app.utils import or_none, to_iso, truncate
from ATTENSE_app.events.event import Event

logger = logging.getLogger("signal-mapper.mapper")


# ── Detection label → scenario ID ────────────────────────────────────────────
# Maps the classifier's internal label to the scenario ID in scenarios.json.

_SCENARIO_ID_MAP: dict[str, str] = {
    "xss":                   "APP-01",
    "command_injection":     "APP-02",
    "directory_traversal":   "APP-03",
    "file_upload_exploit":   "APP-04",
    "csrf":                  "APP-05",
    "broken_authentication": "APP-06",
    "generic":               "APP-00",
}

# ── Detection label → target_type ────────────────────────────────────────────
# Web-layer attacks target the application; auth attacks target the account.

_TARGET_TYPE_MAP: dict[str, str] = {
    "xss":                   "service",
    "command_injection":     "service",
    "directory_traversal":   "service",
    "file_upload_exploit":   "service",
    "csrf":                  "service",
    "broken_authentication": "account",
    "generic":               "host",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_incident_id(alert: WazuhAlert) -> str:
    """
    Mint a per-alert incident ID.

    One Wazuh alert = one ticket. We use Wazuh's own alert id (e.g.
    "1778258112.30741", which is unique per fired rule instance) as the
    incident_id, so each detected attack opens its own incident in
    blueteam instead of every alert piling onto a single shared ticket.

    Falls back to a generated UUID if Wazuh didn't include an id, and
    finally to the legacy INCIDENT_ID env var for backwards compatibility
    in tests / file-output mode where blueteam isn't in the loop.
    """
    wazuh_id = str(alert.raw.get("id", "")).strip()
    if wazuh_id:
        return f"wazuh-{wazuh_id}"
    env_id = os.getenv("INCIDENT_ID")
    if env_id:
        return env_id
    return f"wazuh-{uuid.uuid4()}"


def _build_metadata(alert: WazuhAlert, cls) -> dict:
    """
    Assemble the evidence bag from the Wazuh alert.

    Everything a downstream consumer (state machine, reporting layer,
    blue team UI) might need is preserved here. The Event fields stay
    clean and schema-compliant; all signal-mapper-specific data lives
    in metadata.
    """
    metadata: dict = {
        # Classifier result
        "detection_label":  cls.event_type,
        "severity":         cls.severity,

        # Network attribution — attacker IP lives here, not in actor_id.
        # actor_id = "wazuh" because Wazuh raised this event, not the attacker.
        # Phase 3 correlation engine will use source_ip to attribute the attack.
        "source_ip":        or_none(alert.data.srcip) or or_none(alert.agent.ip),
        "target_ip":        or_none(alert.data.dstip),

        # Wazuh rule internals — preserved for traceability and audit
        "wazuh_rule_id":    or_none(alert.rule.id),
        "wazuh_rule_level": alert.rule.level,
        "description":      or_none(alert.rule.description) or truncate(alert.full_log, 300),

        # Agent — which monitored host produced this log
        "agent_name":       or_none(alert.agent.name),
        "agent_ip":         or_none(alert.agent.ip),
        "location":         or_none(alert.location),

        # Raw snapshot — allows full reconstruction without re-parsing
        "raw_ref": {
            "rule_id":  alert.rule.id,
            "level":    alert.rule.level,
            "groups":   alert.rule.groups,
            "full_log": truncate(alert.full_log, 200),
        },
    }

    # MITRE ATT&CK context — attach if Wazuh provided it (valuable in Phase 4)
    if alert.rule.mitre:
        metadata["mitre"] = alert.rule.mitre

    # Any extra fields from the Wazuh data block
    if alert.data.extra:
        metadata["extra"] = alert.data.extra

    return metadata


# ── Main mapping function ─────────────────────────────────────────────────────

def map_alert(raw: dict) -> Optional[Event]:
    """
    Convert *raw* (a Wazuh alert dict) into a single ATTENSE Event.

    Returns None if the alert cannot be parsed or classified — the caller
    must skip None results silently.

    The emitted event is always:
      event_type = "alert_raised"
      actor_type = "system"
      actor_id   = "wazuh"

    Timestamp semantics
    -------------------
    The timestamp is DETECTION TIME — when Wazuh fired the rule.
    It is NOT execution time — when the attack actually happened.
    The gap between those two points IS the TTD.

    In Phase 2:  start_time = detection_time (TTD = 0, gap not yet observable)
    In Phase 3+: start_time comes earlier from the attacker node (TTD is real)

    The state machine (incident.py) owns this logic — not this mapper.

    Outcome semantics
    -----------------
    "detected"  — Wazuh matched a known attack pattern  (specific scenario)
    None        — Wazuh fired a generic / unclassified rule (no scenario match)
    """

    # ── Step 1: Parse ─────────────────────────────────────────────────────────
    alert: Optional[WazuhAlert] = parse_alert(raw)
    if alert is None:
        return None

    # ── Step 2: Classify ──────────────────────────────────────────────────────
    # cls.event_type is the INTERNAL detection label ("xss", "command_injection")
    # It is NOT the ATTENSE lifecycle event_type.
    cls = classify(alert)

    # ── Step 3: Resolve field values ──────────────────────────────────────────
    scenario_id = _SCENARIO_ID_MAP.get(cls.event_type, "APP-00")
    target_type = _TARGET_TYPE_MAP.get(cls.event_type, "host")
    target_id   = (
        or_none(alert.agent.name)
        or or_none(alert.agent.id)
        or "unknown"
    )
    incident_id = _resolve_incident_id(alert)
    metadata    = _build_metadata(alert, cls)

    # ── Step 4: Determine outcome ──────────────────────────────────────────────
    # A specific scenario match means Wazuh positively identified an attack
    # pattern → "detected".  A generic alert has no scenario match → None.
    outcome = "detected" if cls.event_type != "generic" else None

    # ── Step 5: Build and return the Event ────────────────────────────────────
    event = Event(
        event_id    = str(uuid.uuid4()),   # unique per event — correct to mint here
        incident_id = incident_id,         # externally owned — read from environment
        scenario_id = scenario_id,
        actor_id    = "wazuh",             # the detector, never the attacker
        target_id   = target_id,
        event_type  = "alert_raised",      # the only honest type for a detection signal
        actor_type  = "system",            # Wazuh is a system actor
        target_type = target_type,
        timestamp   = to_iso(alert.timestamp),   # detection time — see docstring
        outcome     = outcome,
        metadata    = metadata,
    )

    logger.info(
        "[mapper] rule=%-6s  scenario=%-6s  event_type=alert_raised  "
        "severity=%-8s  label=%-22s  outcome=%-8s  src=%s",
        alert.rule.id,
        scenario_id,
        cls.severity,
        cls.event_type,
        outcome or "–",
        metadata.get("source_ip") or "–",
    )

    return event