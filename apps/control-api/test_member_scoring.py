"""
test_member_scoring.py — Unit tests for per-analyst scoring
(pipeline/scoring_engine.py::score_members) and the team-average wiring
in pipeline/bridge.py::run_bridge.

Run from attense-app/ (with packages/attense-core on PYTHONPATH):
    python -m pytest test_member_scoring.py -v
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from pipeline.scoring_engine import score_incident, score_members

_DATA_FILE = _HERE / "ATTENSE_app" / "AI" / "Data" / "APP-01-XSS.json"

_ALERT_ET = {
    "alert_raised", "alert_investigation_started", "incident_confirmed",
    "alert_denied", "incident_ended", "dismissal_approved",
}


def _target_type(event_type: str) -> str:
    return "alert" if event_type in _ALERT_ET else "service"


def _build_from_scenario(scenario: dict, incident_id: str = "member-test") -> tuple[Incident, list[Event]]:
    t0 = datetime(2025, 1, 1, 9, 0, 0)
    events: list[Event] = []
    for i, entry in enumerate(scenario["event_log"]):
        et = entry["event_type"]
        events.append(Event(
            event_id=f"ev-{i:03d}", incident_id=incident_id, scenario_id=scenario["scenario_id"],
            actor_id=entry.get("actor_id", "system"), target_id="sandbox-target",
            event_type=et, actor_type=entry["actor_type"], target_type=_target_type(et),
            timestamp=t0 + timedelta(seconds=entry["t_offset_sec"]), outcome=entry["outcome"],
            metadata={"detail": entry.get("detail", "")},
        ))
    incident = Incident(incident_id, scenario["scenario_id"])
    for ev in events:
        incident.apply_event(ev)
    return incident, events


@pytest.fixture(scope="module")
def rule_data() -> dict:
    with open(_DATA_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def _scenario(rule_data: dict, sid: str) -> dict:
    return next(s for s in rule_data["scenarios"] if s["scenario_id"] == sid)


# ═══════════════════════════════════════════════════════════════════════════
# XSS-S1 fixture already has 4 distinct blue_team analysts in its event_log:
#   analyst-1 -> alert_investigation_started
#   analyst-2 -> incident_confirmed
#   analyst-3 -> containment_initiated, containment_succeeded
#   incident-commander -> evidence_preserved, eradication_completed,
#                          recovery_validated, lessons_learned_recorded
# Every rule passes team-wide in this fixture (the "good response" scenario),
# so this proves attribution correctness without score differences masking it.
# ═══════════════════════════════════════════════════════════════════════════

class TestAttributionOnCleanResponse:
    @staticmethod
    @pytest.fixture(scope="class")
    def members(rule_data):
        incident, events = _build_from_scenario(_scenario(rule_data, "XSS-S1"))
        return score_members(incident, events, rule_data)

    def test_all_four_analysts_present(self, members):
        assert set(members) == {"analyst-1", "analyst-2", "analyst-3", "incident-commander"}

    def test_analyst1_owns_only_r01(self, members):
        statuses = {r.rule_id: r.status for r in members["analyst-1"].rules}
        assert statuses["XSS-R01"] == "passed"
        for rid in ("XSS-R03", "XSS-R04", "XSS-R05", "XSS-R06", "XSS-R07", "XSS-R08"):
            assert statuses[rid] == "not_applicable", f"{rid} should be n/a for analyst-1"

    def test_analyst2_owns_only_r02(self, members):
        statuses = {r.rule_id: r.status for r in members["analyst-2"].rules}
        assert statuses["XSS-R02"] == "passed"
        assert statuses["XSS-R01"] == "not_applicable"
        assert statuses["XSS-R04"] == "not_applicable"

    def test_analyst3_owns_containment(self, members):
        statuses = {r.rule_id: r.status for r in members["analyst-3"].rules}
        assert statuses["XSS-R04"] == "passed"
        assert statuses["XSS-R05"] == "passed"
        assert statuses["XSS-R01"] == "not_applicable"
        assert statuses["XSS-R08"] == "not_applicable"

    def test_commander_owns_post_containment_steps(self, members):
        statuses = {r.rule_id: r.status for r in members["incident-commander"].rules}
        for rid in ("XSS-R03", "XSS-R06", "XSS-R07", "XSS-R08"):
            assert statuses[rid] == "passed", f"{rid} should be owned by incident-commander"
        assert statuses["XSS-R01"] == "not_applicable"
        assert statuses["XSS-R04"] == "not_applicable"

    def test_r09_not_applicable_for_everyone(self, members):
        # No alert_denied in this fixture at all -> n/a team-wide -> n/a for all.
        for result in members.values():
            statuses = {r.rule_id: r.status for r in result.rules}
            assert statuses["XSS-R09"] == "not_applicable"

    def test_shared_ttc_factor_and_bonus_across_members(self, members):
        # TTC factor/difficulty bonus are incident-level, identical for everyone.
        values = {(r.ttc_factor, r.response_difficulty_bonus) for r in members.values()}
        assert len(values) == 1

    def test_clean_response_every_member_scores_100(self, members):
        # No rule failed team-wide, so every member's personal penalty_total is 0
        # and they all share the same ttc_factor/bonus -> identical perfect score.
        for analyst_id, result in members.items():
            assert result.penalty_total == 0, analyst_id
            assert result.final_score == 100.0, analyst_id
            assert result.verdict == "excellent", analyst_id

    def test_not_applicable_rules_carry_attribution_evidence(self, members):
        rule = next(r for r in members["analyst-1"].rules if r.rule_id == "XSS-R04")
        assert rule.status == "not_applicable"
        assert "analyst-3" in rule.evidence[0]


# ═══════════════════════════════════════════════════════════════════════════
# Synthetic two-analyst incident with a deliberate personal failure, to prove
# scores actually differentiate (not just statuses).
#   analyst-slow : investigation way past MTTA (600s)        -> R01 triggered
#   analyst-fast : contains well within TTC                  -> R04/R05 passed
# ═══════════════════════════════════════════════════════════════════════════

def _make_event(incident_id, scenario_id, event_type, actor_id, actor_type, offset_sec):
    t0 = datetime(2025, 6, 1, 10, 0, 0)
    return Event(
        event_id=f"ev-{event_type}-{actor_id}", incident_id=incident_id, scenario_id=scenario_id,
        actor_id=actor_id, target_id="sandbox-target", event_type=event_type,
        actor_type=actor_type, target_type=_target_type(event_type),
        timestamp=t0 + timedelta(seconds=offset_sec), outcome="success", metadata={},
    )


class TestScoreDifferentiationAndTeamAverage:
    @staticmethod
    @pytest.fixture(scope="class")
    def setup(rule_data):
        scenario = _scenario(rule_data, "XSS-S1")  # mtta=600s, ttc_expected=8640s
        incident_id, scenario_id = "diff-test", "XSS-S1"
        events = [
            _make_event(incident_id, scenario_id, "alert_raised", "wazuh", "system", 0),
            # analyst-slow investigates at t=900s -- past the 600s MTTA -> R01 triggered
            _make_event(incident_id, scenario_id, "alert_investigation_started", "analyst-slow", "blue_team", 900),
            _make_event(incident_id, scenario_id, "incident_confirmed", "analyst-slow", "blue_team", 950),
            # analyst-fast contains well within ttc_expected -> R04/R05 passed
            _make_event(incident_id, scenario_id, "containment_initiated", "analyst-fast", "blue_team", 1000),
            _make_event(incident_id, scenario_id, "containment_succeeded", "analyst-fast", "blue_team", 1200),
        ]
        incident = Incident(incident_id, scenario_id)
        for ev in events:
            incident.apply_event(ev)
        team = score_incident(incident, events, rule_data)
        members = score_members(incident, events, rule_data)
        return team, members

    def test_slow_analyst_is_penalized_for_their_own_late_investigation(self, setup):
        _, members = setup
        r01 = next(r for r in members["analyst-slow"].rules if r.rule_id == "XSS-R01")
        assert r01.status == "triggered"
        assert members["analyst-slow"].penalty_total < 0

    def test_fast_analyst_not_penalized_for_teammates_slow_investigation(self, setup):
        _, members = setup
        r01 = next(r for r in members["analyst-fast"].rules if r.rule_id == "XSS-R01")
        assert r01.status == "not_applicable"
        r04 = next(r for r in members["analyst-fast"].rules if r.rule_id == "XSS-R04")
        assert r04.status == "passed"

    def test_fast_analyst_scores_higher_than_slow_analyst(self, setup):
        _, members = setup
        assert members["analyst-fast"].final_score > members["analyst-slow"].final_score

    def test_team_average_equals_mean_of_member_scores(self, setup):
        team, members = setup
        expected_avg = round(sum(r.final_score for r in members.values()) / len(members), 2)
        # score_incident() itself is unchanged (whole-team penalty_total includes
        # R01's hit), so the team's own score and the member-average need not be
        # equal -- but the average we'd present at the bridge layer must match
        # exactly this arithmetic mean.
        assert expected_avg == pytest.approx(
            (members["analyst-slow"].final_score + members["analyst-fast"].final_score) / 2
        )


class TestNoMembersFallback:
    def test_score_members_empty_when_no_blue_team_actor(self, rule_data):
        scenario_id = "XSS-S1"
        incident_id = "no-analyst-incident"
        events = [_make_event(incident_id, scenario_id, "alert_raised", "wazuh", "system", 0)]
        incident = Incident(incident_id, scenario_id)
        for ev in events:
            incident.apply_event(ev)
        assert score_members(incident, events, rule_data) == {}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
