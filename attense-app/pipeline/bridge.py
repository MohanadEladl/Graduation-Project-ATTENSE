"""
pipeline/bridge.py — Evaluation Bridge

Loads events from two sources for a given incident_id:
  1. /attense/data/mapped_events.jsonl   — Wazuh/SIEM events (actor_type: system)
  2. /attense/actions/analyst-*.jsonl    — Analyst actions  (actor_type: blue_team)

Maps our internal event types to ATTENSE ALLOWED_EVENT_TYPES, builds Event
objects, feeds them into an Incident in timestamp order, then calls
generate_report() and returns (report_dict, events_list).

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

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report

# ── Paths ─────────────────────────────────────────────────────────────────────
ACTIONS_DIR   = os.environ.get("ACTIONS_LOG_DIR",  "/attense/actions")
MAPPED_EVENTS = os.environ.get("ATTENSE_DATA_PATH", "/attense/data/mapped_events.jsonl")

# ── Event type mapping ────────────────────────────────────────────────────────
ANALYST_EVENT_MAP: dict[str, str] = {
    "investigation_started": "alert_investigation_started",
    "incident_confirmed":    "incident_confirmed",
    "containment_initiated": "containment_initiated",
    "containment_succeeded": "containment_succeeded",
    "incident_ended":        "incident_ended",
    "alert_denied":          "alert_denied",
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
    Load all events for incident_id, build an Incident, call generate_report().
    Returns (report_dict, sorted_events).
    """
    wazuh   = _load_wazuh_events(incident_id)
    analyst = _load_analyst_events(incident_id)
    all_events = sorted(wazuh + analyst, key=lambda e: e.timestamp)

    if not all_events:
        raise ValueError(f"No events found for incident '{incident_id}'")

    scenario_id = all_events[0].scenario_id
    incident = Incident(incident_id, scenario_id)
    for ev in all_events:
        incident.apply_event(ev)

    report = generate_report(incident)
    return report, all_events
