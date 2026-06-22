"""
test_live_scoring.py — Verify the live-incident scoring path in bridge.py.

Builds a synthetic "APP-01" incident (bare attack-type ID, no S1/S2/S3 suffix)
with an alert_raised event carrying metadata["severity"] = "high", exercises
the full _load_rule_data → synthetic-scenario → score_incident chain, and
asserts the result is structurally sound.

Run from attense-app/:
    python3.11 test_live_scoring.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report
from pipeline.bridge import (
    _ATTACK_RULE_FILES,
    _extract_alert_severity,
    _load_rule_data,
    _scoring_to_dict,
)
from pipeline.scoring_engine import score_incident
from ATTENSE_app.AI.live_thresholds import compute_live_thresholds


def _make_event(incident_id, scenario_id, event_type, actor_type, offset_sec, metadata=None):
    target_type = "alert" if event_type in {
        "alert_raised", "alert_investigation_started", "incident_confirmed",
        "alert_denied", "incident_ended", "dismissal_approved",
    } else "service"
    return Event(
        event_id    = f"ev-{event_type}",
        incident_id = incident_id,
        scenario_id = scenario_id,
        actor_id    = "analyst-01" if actor_type == "blue_team" else "wazuh",
        target_id   = "sandbox-target",
        event_type  = event_type,
        actor_type  = actor_type,
        target_type = target_type,
        timestamp   = datetime(2025, 6, 1, 10, 0, 0) + timedelta(seconds=offset_sec),
        outcome     = "success",
        metadata    = metadata or {},
    )


def main():
    INC = "INC-LIVE-001"
    SID = "APP-01"   # bare attack-type ID — no S1/S2/S3

    # ── 1. Verify _load_rule_data accepts the new APP-0X key format ───────────
    assert "APP-01" in _ATTACK_RULE_FILES, f"APP-01 not in _ATTACK_RULE_FILES: {sorted(_ATTACK_RULE_FILES)}"
    rule_data = _load_rule_data(SID)
    print(f"[OK] _load_rule_data('APP-01') loaded {len(rule_data['scenarios'])} scenarios")

    # Confirm none of the scenario_ids match "APP-01" — that's the whole point
    known = {s["scenario_id"] for s in rule_data.get("scenarios", [])}
    assert SID not in known, f"'APP-01' unexpectedly found in scenario IDs: {known}"
    print(f"[OK] 'APP-01' is not in fixture scenario IDs {known} — live path will trigger")

    # ── 2. Build a minimal live-style event stream ────────────────────────────
    # alert_raised must carry metadata["severity"] so _extract_alert_severity works
    events = [
        _make_event(INC, SID, "alert_raised",               "system",     0,    {"severity": "high"}),
        _make_event(INC, SID, "alert_investigation_started","blue_team",  300),
        _make_event(INC, SID, "incident_confirmed",          "blue_team",  600),
        _make_event(INC, SID, "evidence_preserved",          "blue_team",  900),
        _make_event(INC, SID, "containment_initiated",       "blue_team", 1200),
        _make_event(INC, SID, "containment_succeeded",       "blue_team", 3900),
        _make_event(INC, SID, "eradication_completed",       "blue_team", 4200),
        _make_event(INC, SID, "recovery_validated",          "blue_team", 4500),
        _make_event(INC, SID, "lessons_learned_recorded",   "blue_team", 4800),
        _make_event(INC, SID, "incident_ended",              "blue_team", 5100),
    ]

    # ── 3. Verify _extract_alert_severity reads from real event metadata ──────
    severity = _extract_alert_severity(events)
    assert severity == "high", f"Expected 'high', got '{severity}'"
    print(f"[OK] _extract_alert_severity() returned '{severity}' from event metadata (not hardcoded)")

    # ── 4. Confirm "critical" → "very_high" normalisation ────────────────────
    crit_events = [
        _make_event(INC, SID, "alert_raised", "system", 0, {"severity": "critical"}),
    ]
    normalised = _extract_alert_severity(crit_events)
    assert normalised == "very_high", f"Expected 'very_high' for 'critical', got '{normalised}'"
    print(f"[OK] 'critical' → '{normalised}' normalisation applied (R09 would otherwise silently not trigger)")

    # ── 5. Confirm ValueError when alert_raised has no severity ──────────────
    no_sev_events = [
        _make_event(INC, SID, "alert_raised", "system", 0, {}),
    ]
    try:
        _extract_alert_severity(no_sev_events)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"[OK] Missing severity raises ValueError (not a silent default): {e}")

    # ── 6. Build incident and run the full scoring path ───────────────────────
    incident = Incident(INC, SID)
    for ev in events:
        incident.apply_event(ev)

    report = generate_report(incident)

    # Replicate exactly what run_bridge() now does for live incidents
    known_ids = {s["scenario_id"] for s in rule_data.get("scenarios", [])}
    assert SID not in known_ids   # confirms live path will execute

    live = compute_live_thresholds(SID)
    synthetic = {
        "scenario_id": SID,
        "computed_thresholds": {
            "mtta_threshold_sec": live["mtta_threshold_sec"],
            "ttc_expected_sec":   live["ttc_expected_sec"],
            "ttc_max_sec":        live["ttc_max_sec"],
        },
        "alert_severity": _extract_alert_severity(events),
        "detection":      {"difficulty": live["detection_difficulty"]},
    }
    live_rule_data = {**rule_data, "scenarios": rule_data.get("scenarios", []) + [synthetic]}

    scoring = score_incident(incident, events, live_rule_data)
    report.update(_scoring_to_dict(scoring))

    print(f"\n[RESULT]")
    print(f"  scenario_id:      {SID}")
    print(f"  alert_severity:   {synthetic['alert_severity']}  (from event metadata, not hardcoded)")
    print(f"  detection.difficulty: {live['detection_difficulty']}  (from live_thresholds)")
    print(f"  ttc_expected_sec: {live['ttc_expected_sec']}")
    print(f"  ttc_max_sec:      {live['ttc_max_sec']}")
    print(f"  mtta_threshold_sec: {live['mtta_threshold_sec']}")
    print(f"  final_score:      {report['final_score']}")
    print(f"  verdict:          {report['verdict']}")
    print(f"  penalty_total:    {report['penalty_total']}")
    print(f"  ttc_factor:       {report['ttc_factor']}")
    print(f"  scoring_rules:    {len(report['scoring_rules'])} rules evaluated")

    # Structural assertions — not checking exact score since containment timing
    # will differ from XSS-S1 fixture (same events, different thresholds apply)
    assert isinstance(report["final_score"], float)
    assert report["verdict"] in ("excellent", "acceptable", "needs_review", "failed")
    assert len(report["scoring_rules"]) == 9
    assert report["ttc_factor"] > 0, "ttc_factor should be > 0 (containment within window)"

    # Cross-check thresholds against known XSS-S1 fixture values
    assert live["ttc_expected_sec"] == 8640.0, f"APP-01 ttc_expected wrong: {live['ttc_expected_sec']}"
    assert live["ttc_max_sec"]      == 12960.0
    assert live["mtta_threshold_sec"] == 600
    print(f"\n[OK] Thresholds match XSS-S1 fixture values (8640 / 12960 / 600)")

    print(f"\nAll assertions passed.")


if __name__ == "__main__":
    main()
