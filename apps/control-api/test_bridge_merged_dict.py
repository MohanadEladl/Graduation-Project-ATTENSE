"""
test_bridge_merged_dict.py — Synthetic demonstration of the merged dict.

Exercises the full run_bridge() integration path using XSS-S1 events built
from the JSON fixture (no Docker, no Gemini).  The test bypasses the
file-system loaders (_load_wazuh_events / _load_analyst_events) that need
live containers and instead calls the internal helpers directly.

Run from attense-app/:
    python3.11 test_bridge_merged_dict.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from pprint import pformat

_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report
from pipeline.bridge import _load_rule_data, _scoring_to_dict
from pipeline.scoring_engine import score_incident

# ── Build a real XSS-S1 incident from the JSON fixture ───────────────────────

_DATA_FILE = _HERE / "ATTENSE_app" / "AI" / "Data" / "APP-01-XSS.json"

_ALERT_ET = {
    "alert_raised",
    "alert_investigation_started",
    "incident_confirmed",
    "alert_denied",
    "incident_ended",
    "dismissal_approved",
}


def _target_type(event_type: str) -> str:
    return "alert" if event_type in _ALERT_ET else "service"


def _build_xss_s1() -> tuple[Incident, list[Event]]:
    with open(_DATA_FILE, encoding="utf-8") as fh:
        rule_data = json.load(fh)

    scenario = next(s for s in rule_data["scenarios"] if s["scenario_id"] == "XSS-S1")
    t0 = datetime(2025, 1, 1, 9, 0, 0)
    events: list[Event] = []

    for i, entry in enumerate(scenario["event_log"]):
        et = entry["event_type"]
        events.append(Event(
            event_id    = f"ev-{i:03d}",
            incident_id = "demo-incident-001",
            scenario_id = "XSS-S1",
            actor_id    = entry.get("actor_id", "system"),
            target_id   = "sandbox-target",
            event_type  = et,
            actor_type  = entry["actor_type"],
            target_type = _target_type(et),
            timestamp   = t0 + timedelta(seconds=entry["t_offset_sec"]),
            outcome     = entry["outcome"],
            metadata    = {"detail": entry.get("detail", ""), "t_offset_sec": entry["t_offset_sec"]},
        ))

    # XSS-S1 fixture ends at lessons_learned_recorded (t=4800s) with no incident_ended.
    # outcome.py requires status=="ENDED" (set only by incident_ended) to return "SUCCESS".
    # Add the terminal event here so the test reflects a complete incident lifecycle.
    events.append(Event(
        event_id    = "ev-terminal",
        incident_id = "demo-incident-001",
        scenario_id = "XSS-S1",
        actor_id    = "incident-commander",
        target_id   = "sandbox-target",
        event_type  = "incident_ended",
        actor_type  = "blue_team",
        target_type = "alert",
        timestamp   = t0 + timedelta(seconds=5100),
        outcome     = "success",
        metadata    = {"detail": "Incident formally closed after lessons-learned review.", "t_offset_sec": 5100},
    ))

    incident = Incident("demo-incident-001", "XSS-S1")
    for ev in events:
        incident.apply_event(ev)

    return incident, events, rule_data


def main() -> None:
    incident, all_events, rule_data = _build_xss_s1()

    # Step 1: generate_report() — same as bridge.py does
    report = generate_report(incident)

    # Step 2: score_incident() — same as bridge.py does
    scoring = score_incident(incident, all_events, rule_data)

    # Step 3: merge — same as bridge.py does (report.update(...))
    report.update(_scoring_to_dict(scoring))

    # Print the merged dict with non-serialisable types converted for display
    def serialise(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, timedelta):
            return obj.total_seconds()
        return str(obj)

    print("\n" + "=" * 72)
    print("MERGED DICT — run_bridge() output for XSS-S1 (demo-incident-001)")
    print("=" * 72)
    print(json.dumps(report, default=serialise, indent=2))

    # ── Assertions ─────────────────────────────────────────────────────────────
    # report.py keys
    assert report["incident_id"]  == "demo-incident-001"
    assert report["scenario_id"]  == "XSS-S1"
    assert report["outcome"]      == "SUCCESS"                 # uppercase — timestamp-based
    assert isinstance(report["ttd"], timedelta)
    assert isinstance(report["ttc"], timedelta)

    # scoring_engine keys
    assert report["final_score"]  == 100.0
    assert report["verdict"]      == "excellent"              # lowercase — score-based
    assert report["penalty_total"] == 0
    assert report["ttc_factor"]   == 1.0
    assert report["ttc_actual_sec"] is not None
    assert report["response_difficulty_bonus"] > 0
    assert len(report["scoring_rules"]) == 9

    # The two concepts must coexist under distinct names and never collide
    assert report["outcome"] != report["verdict"], (
        "'outcome' and 'verdict' must not be the same value"
    )

    # Every rule dict has the right keys
    required_rule_keys = {"rule_id", "description", "penalty_points", "status", "evidence"}
    for rule in report["scoring_rules"]:
        assert required_rule_keys == set(rule.keys()), f"Bad keys in rule: {rule}"
        assert rule["status"] in ("triggered", "passed", "not_applicable")

    print("\n" + "=" * 72)
    print("All assertions passed.")
    print("=" * 72)


if __name__ == "__main__":
    main()
