"""
pipeline/run_gemini_test.py — Gemini prompt validation script.

Builds synthetic incidents from the JSON fixtures (bypassing the live
event loaders) and runs the full generate() call through Gemini.
Used for validating prompt output without needing live TheHive/Wazuh data.

Usage (from inside the container, env vars already set):
    python3 -m pipeline.run_gemini_test
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report
from pipeline.bridge import _load_rule_data, _scoring_to_dict
from pipeline.report_generator import generate
from pipeline.scoring_engine import score_incident

_DATA_DIR = Path(__file__).parent.parent / "ATTENSE_app" / "AI" / "Data"

_ALERT_ET = {
    "alert_raised", "alert_investigation_started", "incident_confirmed",
    "alert_denied", "incident_ended", "dismissal_approved",
}


def _target_type(et: str) -> str:
    return "alert" if et in _ALERT_ET else "service"


def _build(data_file: Path, scenario_id: str, incident_id: str,
           add_terminal: bool = False) -> tuple[Incident, list[Event], dict]:
    with open(data_file, encoding="utf-8") as fh:
        rule_data = json.load(fh)

    scenario = next(
        s for s in rule_data["scenarios"] if s["scenario_id"] == scenario_id
    )
    t0 = datetime(2025, 1, 1, 9, 0, 0)
    events: list[Event] = []

    for i, entry in enumerate(scenario["event_log"]):
        et = entry["event_type"]
        events.append(Event(
            event_id    = f"ev-{i:03d}",
            incident_id = incident_id,
            scenario_id = scenario_id,
            actor_id    = entry.get("actor_id", "system"),
            target_id   = "sandbox-target",
            event_type  = et,
            actor_type  = entry["actor_type"],
            target_type = _target_type(et),
            timestamp   = t0 + timedelta(seconds=entry["t_offset_sec"]),
            outcome     = entry["outcome"],
            metadata    = {
                "detail":       entry.get("detail", ""),
                "t_offset_sec": entry["t_offset_sec"],
            },
        ))

    if add_terminal:
        last_offset = max(e["t_offset_sec"] for e in scenario["event_log"])
        events.append(Event(
            event_id    = "ev-terminal",
            incident_id = incident_id,
            scenario_id = scenario_id,
            actor_id    = "incident-commander",
            target_id   = "sandbox-target",
            event_type  = "incident_ended",
            actor_type  = "blue_team",
            target_type = "alert",
            timestamp   = t0 + timedelta(seconds=last_offset + 300),
            outcome     = "success",
            metadata    = {
                "detail":       "Incident formally closed after post-incident review.",
                "t_offset_sec": last_offset + 300,
            },
        ))

    incident = Incident(incident_id, scenario_id)
    for ev in events:
        incident.apply_event(ev)

    return incident, events, rule_data


def _run_scenario(label: str, data_file: Path, scenario_id: str,
                  incident_id: str, add_terminal: bool = False) -> None:
    SEP = "=" * 72
    print(f"\n{SEP}")
    print(f"  {label}")
    print(f"  scenario: {scenario_id}  |  incident: {incident_id}")
    print(f"{SEP}\n")

    incident, events, rule_data = _build(
        data_file, scenario_id, incident_id, add_terminal=add_terminal
    )
    report = generate_report(incident)
    report.update(_scoring_to_dict(score_incident(incident, events, rule_data)))
    report["mitre_attack"]       = rule_data.get("mitre_attack", {})
    report["response_framework"] = rule_data.get("response_framework", {})

    print(f"  Score: {report['final_score']}/100  Verdict: {report['verdict']}"
          f"  Outcome: {report['outcome']}  Penalty: {report['penalty_total']}pts")
    triggered = [r for r in report["scoring_rules"] if r["status"] == "triggered"]
    print(f"  Triggered rules: {[r['rule_id'] for r in triggered] or 'none'}\n")

    markdown = generate(report, events)

    # Print the full report, then extract and highlight the two key sections
    print(markdown)

    print(f"\n{'-'*72}")
    print("  EXTRACTED: ## Attack Context")
    print(f"{'-'*72}")
    lines = markdown.splitlines()
    in_section, found = False, False
    for line in lines:
        if line.strip().startswith("## Attack Context"):
            in_section, found = True, False
        elif in_section and line.startswith("## "):
            break
        elif in_section:
            print(line)
    if not found:
        print("  (section not found in output)")

    if triggered:
        print(f"\n{'-'*72}")
        print("  EXTRACTED: ## Score Breakdown")
        print(f"{'-'*72}")
        in_section = False
        for line in lines:
            if line.strip().startswith("## Score Breakdown"):
                in_section = True
            elif in_section and line.startswith("## "):
                break
            elif in_section:
                print(line)


if __name__ == "__main__":
    _run_scenario(
        label       = "SCENARIO 1 — XSS-S1 (clean success, all rules pass)",
        data_file   = _DATA_DIR / "APP-01-XSS.json",
        scenario_id = "XSS-S1",
        incident_id = "INC-2025-0042",
        add_terminal= True,
    )

    _run_scenario(
        label       = "SCENARIO 2 — CMDI-S2 (failures: delayed triage, alert denied without approval)",
        data_file   = _DATA_DIR / "APP-02-CMDI.json",
        scenario_id = "CMDI-S2",
        incident_id = "INC-2025-0099",
        add_terminal= False,
    )
