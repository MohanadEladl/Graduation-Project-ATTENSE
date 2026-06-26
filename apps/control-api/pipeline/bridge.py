"""
pipeline/bridge.py — Evaluation Bridge

Loads events from two sources for a given incident_id:
  1. /attense/data/mapped_events.jsonl   — Wazuh/SIEM events (actor_type: system)
  2. /attense/actions/analyst-*.jsonl    — Analyst actions  (actor_type: blue_team)

Maps our internal event types to ATTENSE ALLOWED_EVENT_TYPES, builds Event
objects, feeds them into an Incident in timestamp order, then calls
generate_report() and score_incident() and returns the merged dict plus the
sorted events list.

Returned dict — two clearly distinct evaluation concepts
---------------------------------------------------------
outcome   (str, uppercase)  — timestamp-presence-based classification from
                              report.py: SUCCESS / PARTIAL / FAILURE /
                              FALSE_POSITIVE / INCOMPLETE
verdict   (str, lowercase)  — score-based band from scoring_engine.py:
                              excellent / acceptable / needs_review / failed

These are different things and must never be merged or treated as equivalent.

Additional scoring keys in the returned dict
--------------------------------------------
final_score               float
verdict                   str   (see above)
penalty_total             int
ttc_factor                float
ttc_actual_sec            float | None
response_difficulty_bonus float
scoring_rules             list[dict]  — all 9 rules with status + evidence;
                          the Gemini report layer reads this for grounded
                          per-rule feedback

Event type mapping
------------------
Analyst action types         → ATTENSE ALLOWED_EVENT_TYPES
investigation_started        → alert_investigation_started
incident_confirmed           → incident_confirmed          (identity)
containment_initiated        → containment_initiated       (identity)
containment_succeeded        → containment_succeeded       (identity)
incident_ended               → incident_ended              (identity)
alert_denied                 → alert_denied                (identity)

Wazuh mapped_events are expected to already carry valid ATTENSE event types
(the signal-store emits alert_raised / malicious_action_executed etc.).
"""

from __future__ import annotations

import glob
import json
import os
import sys
from datetime import datetime
from typing import Optional

# Ensure ATTENSE_app is importable when run from /app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from attense_core.models.event import Event
from attense_core.models.incident import Incident
from attense_core.evaluation.reports import generate_report
from pipeline.scoring_engine import ScoringResult, score_incident
from ATTENSE_app.AI.live_thresholds import compute_live_thresholds

# ── Paths ─────────────────────────────────────────────────────────────────────
ACTIONS_DIR   = os.environ.get("ACTIONS_LOG_DIR",  "/attense/actions")
MAPPED_EVENTS = os.environ.get("ATTENSE_DATA_PATH", "/attense/data/mapped_events.jsonl")
# Phase 3 durable store. Holds every event that passed through
# controller.process_event() -- the Wazuh file-tail AND the red-team's
# HTTP-ingested malicious_action_executed events (which never reach
# mapped_events.jsonl). Unset -> the store is skipped and scoring falls back to
# the Wazuh-only behaviour.
EVENT_STORE_DIR = os.environ.get("ATTENSE_EVENT_STORE_DIR")

_RULE_DATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ATTENSE_app", "AI", "Data")
)

_ATTACK_RULE_FILES: dict[str, str] = {
    "APP-01": "APP-01-XSS.json",
    "APP-02": "APP-02-CMDI.json",
    "APP-03": "APP-03-DIR.json",
    "APP-04": "APP-04-FUP.json",
    "APP-05": "APP-05-CSRF.json",
    "APP-06": "APP-06-BA.json",
}

# ── Rule data loader ──────────────────────────────────────────────────────────

def _load_rule_data(scenario_id: str) -> dict:
    """
    Derive the attack type from a scenario_id such as 'XSS-S1' or 'CMDI-S2',
    then load and return the corresponding rule JSON.

    Raises ValueError (not FileNotFoundError) for:
      - unrecognised attack type prefix
      - rule file present in the map but missing on disk
    """
    filename = _ATTACK_RULE_FILES.get(scenario_id)
    if filename is None:
        raise ValueError(
            f"No rule file registered for scenario_id '{scenario_id}'. "
            f"Known IDs: {sorted(_ATTACK_RULE_FILES)}"
        )
    path = os.path.join(_RULE_DATA_DIR, filename)
    if not os.path.isfile(path):
        raise ValueError(
            f"Rule file for scenario_id '{scenario_id}' not found on disk: {path}"
        )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _scoring_to_dict(result: ScoringResult) -> dict:
    """
    Serialise a ScoringResult into plain JSON-compatible types.

    Key naming note
    ---------------
    'verdict'  (lowercase band: excellent/acceptable/needs_review/failed)
               lives here and is score-based.
    'outcome'  (uppercase: SUCCESS/PARTIAL/FAILURE/FALSE_POSITIVE/INCOMPLETE)
               comes from report.py and is timestamp-presence-based.
    Both will coexist in the merged report dict — they must never be confused.
    """
    return {
        "final_score":               result.final_score,
        "verdict":                   result.verdict,
        "penalty_total":             result.penalty_total,
        "ttc_factor":                result.ttc_factor,
        "ttc_actual_sec":            result.ttc_actual_sec,
        "response_difficulty_bonus": result.response_difficulty_bonus,
        "scoring_rules": [
            {
                "rule_id":       r.rule_id,
                "description":   r.description,
                "penalty_points": r.penalty_points,
                "status":        r.status,
                "evidence":      r.evidence,
            }
            for r in result.rules
        ],
    }


# ── Live-incident alert severity ──────────────────────────────────────────────

# classifier vocabulary → scoring_engine vocabulary
# The signal-store classifier emits "critical"; _SEVERITY_RANK in scoring_engine uses "very_high".
# Passing "critical" through unchanged would make _SEVERITY_RANK.get("critical", 0) return 0,
# silently treating every critical-severity denial as below-medium and never triggering R09.
_SEVERITY_NORMALIZE: dict[str, str] = {
    "low":       "low",
    "medium":    "medium",
    "high":      "high",
    "critical":  "very_high",
    "very_high": "very_high",
}


def _extract_alert_severity(events: list[Event]) -> str:
    """
    Read alert_severity from the first alert_raised event's metadata.
    Normalises "critical" → "very_high" to match scoring_engine's _SEVERITY_RANK vocabulary.
    Raises ValueError rather than defaulting if the event or field is absent.
    """
    alert_ev = next((e for e in events if e.event_type == "alert_raised"), None)
    if alert_ev is None:
        raise ValueError(
            "Cannot determine alert_severity: no alert_raised event in event stream"
        )
    raw = (alert_ev.metadata or {}).get("severity")
    if not raw:
        raise ValueError(
            "Cannot determine alert_severity: alert_raised event has no 'severity' in metadata"
        )
    normalized = _SEVERITY_NORMALIZE.get(raw)
    if normalized is None:
        raise ValueError(
            f"Unrecognised alert severity '{raw}' in alert_raised metadata. "
            f"Expected one of: {sorted(_SEVERITY_NORMALIZE)}"
        )
    return normalized


# ── Event type mapping ────────────────────────────────────────────────────────
ANALYST_EVENT_MAP: dict[str, str] = {
    "investigation_started":    "alert_investigation_started",  # watcher name → canonical
    "incident_confirmed":       "incident_confirmed",
    "containment_initiated":    "containment_initiated",
    "containment_succeeded":    "containment_succeeded",
    "incident_ended":           "incident_ended",
    "alert_denied":             "alert_denied",
    # v2.0.0 — post-containment events (identity mappings — names are already canonical)
    "evidence_preserved":       "evidence_preserved",
    "eradication_completed":    "eradication_completed",
    "recovery_validated":       "recovery_validated",
    "dismissal_approved":       "dismissal_approved",
    "lessons_learned_recorded": "lessons_learned_recorded",
}

# Detection events → target_type "alert"; containment/attack → "service"
_DETECTION_EVENTS = {
    "alert_raised",
    "alert_investigation_started",
    "incident_confirmed",
    "alert_denied",
    "incident_ended",
}


def _target_type(event_type: str) -> str:
    return "alert" if event_type in _DETECTION_EVENTS else "service"


def _outcome(event_type: str) -> Optional[str]:
    if event_type == "alert_denied":
        return "false_positive"
    return "success"


def _to_datetime(ts) -> datetime:
    """Convert float epoch, ISO string, or datetime to a naive datetime."""
    if isinstance(ts, datetime):
        return ts.replace(tzinfo=None)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts))
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now()


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_wazuh_events(incident_id: str) -> list[Event]:
    events: list[Event] = []
    if not os.path.exists(MAPPED_EVENTS):
        return events
    with open(MAPPED_EVENTS, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("incident_id") != incident_id:
                continue
            try:
                meta = d.get("metadata") or {}
                target_id = (
                    d.get("target_id")
                    or meta.get("target_id")
                    or "sandbox-target"
                )
                events.append(Event(
                    event_id    = d.get("event_id", f"wazuh-{idx}"),
                    incident_id = incident_id,
                    scenario_id = d.get("scenario_id", "APP-00"),
                    actor_id    = d.get("actor_id", "wazuh"),
                    target_id   = target_id,
                    event_type  = d["event_type"],
                    actor_type  = "system",
                    target_type = _target_type(d["event_type"]),
                    timestamp   = _to_datetime(d.get("timestamp")),
                    outcome     = d.get("outcome"),
                    metadata    = meta,
                ))
            except (KeyError, ValueError):
                continue
    return events


def _load_durable_events(incident_id: str) -> list[Event]:
    """Events for the incident from the Phase 3 durable store -- crucially the
    red-team `malicious_action_executed` events, which arrive via HTTP ingest
    (controller.process_event) and never touch mapped_events.jsonl, so they
    anchor the incident's true start_time. Returns [] when the store is
    unconfigured/empty (preserving the original Wazuh-only behaviour).

    Reuses EventRepository (read + dedup + ordering) and
    StandardEvent.to_legacy_event() (the same adapter the controller ingests
    with) instead of re-parsing the on-disk format.
    """
    if not EVENT_STORE_DIR or not os.path.exists(
        os.path.join(EVENT_STORE_DIR, "events.jsonl")
    ):
        return []
    from attense_core.repositories.events import EventRepository

    events: list[Event] = []
    for se in EventRepository(EVENT_STORE_DIR).get_events(incident_id):
        ev = se.to_legacy_event()
        # The store is tz-aware UTC; the bridge works in naive UTC (see
        # _to_datetime). Normalise so the merged timeline sorts/subtracts cleanly.
        if isinstance(ev.timestamp, datetime) and ev.timestamp.tzinfo is not None:
            ev.timestamp = ev.timestamp.replace(tzinfo=None)
        events.append(ev)
    return events


def _load_analyst_events(incident_id: str) -> list[Event]:
    events: list[Event] = []
    pattern = os.path.join(ACTIONS_DIR, "analyst-*.jsonl")
    for path in sorted(glob.glob(pattern)):
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("incident_id") != incident_id:
                    continue
                raw_et  = d.get("event_type", "")
                mapped  = ANALYST_EVENT_MAP.get(raw_et)
                if not mapped:
                    continue
                try:
                    events.append(Event(
                        event_id    = f"act-{d['analyst_id']}-{idx}",
                        incident_id = incident_id,
                        scenario_id = d.get("scenario_id", "APP-00"),
                        actor_id    = d["analyst_id"],
                        target_id   = "sandbox-target",
                        event_type  = mapped,
                        actor_type  = "blue_team",
                        target_type = _target_type(mapped),
                        timestamp   = _to_datetime(d.get("stored_at") or d.get("timestamp")),
                        outcome     = _outcome(mapped),
                        metadata    = {
                            "detail":       d.get("detail", ""),
                            "t_offset_sec": d.get("t_offset_sec", 0),
                        },
                    ))
                except (KeyError, ValueError):
                    continue
    return events


# ── Public entry point ────────────────────────────────────────────────────────

def run_bridge(incident_id: str) -> tuple[dict, list[Event]]:
    """
    Load all events for incident_id, build an Incident, then:
      1. Call generate_report() → 10-key dict including 'outcome' (uppercase,
         timestamp-presence-based: SUCCESS/PARTIAL/FAILURE/FALSE_POSITIVE/INCOMPLETE)
      2. Call score_incident() → ScoringResult with 'verdict' (lowercase,
         score-based: excellent/acceptable/needs_review/failed) plus full
         rule breakdown and numeric scores
      3. Merge both into a single dict and return it with the sorted event list.

    The two evaluation concepts are kept under distinct keys:
      outcome  — from report.py   (classification of what happened)
      verdict  — from scoring_engine.py (quality of the response)
    """
    wazuh   = _load_wazuh_events(incident_id)
    durable = _load_durable_events(incident_id)
    analyst = _load_analyst_events(incident_id)

    # Merge all three sources, deduping by event_id. The durable store also
    # contains the Wazuh alert_raised events (they pass through process_event),
    # so the file-tail copy wins on overlap and the store contributes only the
    # attacker-side events (malicious_action_executed) unique to it.
    by_id: dict[str, Event] = {}
    for ev in wazuh + durable + analyst:
        by_id.setdefault(ev.event_id, ev)
    all_events = sorted(by_id.values(), key=lambda e: e.timestamp)

    if not all_events:
        raise ValueError(f"No events found for incident '{incident_id}'")

    scenario_id = all_events[0].scenario_id
    incident = Incident(incident_id, scenario_id)
    for ev in all_events:
        incident.apply_event(ev)

    report = generate_report(incident)

    rule_data = _load_rule_data(scenario_id)

    known_ids = {s["scenario_id"] for s in rule_data.get("scenarios", [])}
    if scenario_id not in known_ids:
        # Live incident: scenario_id is "APP-0X" with no matching scenario block.
        # Build a synthetic scenario from compute_live_thresholds() + real event severity.
        live = compute_live_thresholds(scenario_id)
        synthetic = {
            "scenario_id": scenario_id,
            "computed_thresholds": {
                "mtta_threshold_sec": live["mtta_threshold_sec"],
                "ttc_expected_sec":   live["ttc_expected_sec"],
                "ttc_max_sec":        live["ttc_max_sec"],
            },
            "alert_severity": _extract_alert_severity(all_events),
            "detection":      {"difficulty": live["detection_difficulty"]},
        }
        rule_data = {**rule_data, "scenarios": rule_data.get("scenarios", []) + [synthetic]}

    scoring = score_incident(incident, all_events, rule_data)
    report.update(_scoring_to_dict(scoring))
    report["mitre_attack"]       = rule_data.get("mitre_attack", {})
    report["response_framework"] = rule_data.get("response_framework", {})

    return report, all_events
