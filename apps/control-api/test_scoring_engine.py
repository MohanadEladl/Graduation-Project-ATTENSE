"""
test_scoring_engine.py — Unit tests for pipeline/scoring_engine.py

Fixtures are built from the three XSS scenarios in APP-01-XSS.json.
Expected statuses come from the independent manual trace, NOT from the
expected_evaluation block in the JSON — this file IS the correctness check.

Run from attense-app/:
    python -m pytest test_scoring_engine.py -v
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# ── Path: ensure attense-app/ is importable from anywhere ────────────────────
_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from pipeline.scoring_engine import ScoringResult, score_incident

# ── Data file ─────────────────────────────────────────────────────────────────

_DATA_FILE = _HERE / "ATTENSE_app" / "AI" / "Data" / "APP-01-XSS.json"

# Detection events → target_type "alert"; all others → "service"
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


# ── Incident builder ──────────────────────────────────────────────────────────

def _build(scenario: dict, incident_id: str = "test-incident") -> tuple[Incident, list[Event]]:
    """
    Construct an Incident and its Event list from a scenario's event_log.
    Anchors timestamps to 2025-01-01 09:00:00 + t_offset_sec so offsets
    in the index will exactly equal the JSON t_offset_sec values.
    """
    t0 = datetime(2025, 1, 1, 9, 0, 0)
    events: list[Event] = []

    for i, entry in enumerate(scenario["event_log"]):
        et = entry["event_type"]
        events.append(
            Event(
                event_id    = f"ev-{i:03d}",
                incident_id = incident_id,
                scenario_id = scenario["scenario_id"],
                actor_id    = entry.get("actor_id", "system"),
                target_id   = "sandbox-target",
                event_type  = et,
                actor_type  = entry["actor_type"],
                target_type = _target_type(et),
                timestamp   = t0 + timedelta(seconds=entry["t_offset_sec"]),
                outcome     = entry["outcome"],
                metadata    = {"detail": entry.get("detail", "")},
            )
        )

    incident = Incident(incident_id, scenario["scenario_id"])
    for ev in events:
        incident.apply_event(ev)

    return incident, events


# ── Module-scoped fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rule_data() -> dict:
    with open(_DATA_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def _scenario(rule_data: dict, sid: str) -> dict:
    return next(s for s in rule_data["scenarios"] if s["scenario_id"] == sid)


@pytest.fixture(scope="module")
def s1_result(rule_data: dict) -> ScoringResult:
    incident, events = _build(_scenario(rule_data, "XSS-S1"))
    return score_incident(incident, events, rule_data)


@pytest.fixture(scope="module")
def s2_result(rule_data: dict) -> ScoringResult:
    incident, events = _build(_scenario(rule_data, "XSS-S2"))
    return score_incident(incident, events, rule_data)


@pytest.fixture(scope="module")
def s3_result(rule_data: dict) -> ScoringResult:
    incident, events = _build(_scenario(rule_data, "XSS-S3"))
    return score_incident(incident, events, rule_data)


# ── Helper ────────────────────────────────────────────────────────────────────

def _statuses(result: ScoringResult) -> dict[str, str]:
    return {r.rule_id: r.status for r in result.rules}


def _penalties(result: ScoringResult) -> dict[str, int]:
    return {r.rule_id: r.penalty_points for r in result.rules}


# ═══════════════════════════════════════════════════════════════════════════════
# XSS-S1 — Stored XSS, good response
#
# cvss=7.6, difficulty=low, mtta=600s, ttc_expected=8640s, ttc_max=12960s
# containment_succeeded at t=3900s  →  ttc_factor=1.0
# difficulty_bonus: low(1), inv_delay=360  →  min(4500/360, 25) = 12.5
# final_score: clamp(round(100 * 1.0 + 12.5, 2), 0, 100) = 100
# ═══════════════════════════════════════════════════════════════════════════════

class TestXSSS1:
    def test_final_score(self, s1_result):
        assert s1_result.final_score == 100.0

    def test_verdict(self, s1_result):
        assert s1_result.verdict == "excellent"

    def test_penalty_total(self, s1_result):
        assert s1_result.penalty_total == 0

    def test_ttc_actual_sec(self, s1_result):
        # containment_succeeded at t_offset=3900s
        assert s1_result.ttc_actual_sec == pytest.approx(3900.0)

    def test_ttc_factor(self, s1_result):
        # 3900 ≤ 8640 (ttc_expected) → 1.0
        assert s1_result.ttc_factor == pytest.approx(1.0)

    def test_difficulty_bonus(self, s1_result):
        # difficulty=low → numeric=1; inv_delay=360 → min(4500*1/360, 25) = 12.5
        assert s1_result.response_difficulty_bonus == pytest.approx(12.5)

    def test_rule_statuses(self, s1_result):
        st = _statuses(s1_result)
        assert st["XSS-R01"] == "passed"          # inv at 360s < mtta 600s
        assert st["XSS-R02"] == "passed"          # incident_confirmed present
        assert st["XSS-R03"] == "passed"          # evidence (3540s) before containment_init (3600s)
        assert st["XSS-R04"] == "passed"          # containment_init (3600s) < ttc_max (12960s)
        assert st["XSS-R05"] == "passed"          # containment_succeeded present
        assert st["XSS-R06"] == "passed"          # eradication (4200s) after containment_ok (3900s)
        assert st["XSS-R07"] == "passed"          # recovery (4500s) after eradication (4200s)
        assert st["XSS-R08"] == "passed"          # lessons (4800s) after recovery (4500s)
        assert st["XSS-R09"] == "not_applicable"  # no alert_denied event

    def test_no_triggered_rules(self, s1_result):
        triggered = [r.rule_id for r in s1_result.rules if r.status == "triggered"]
        assert triggered == [], f"Unexpected triggered rules: {triggered}"

    def test_all_rules_present(self, s1_result):
        assert len(s1_result.rules) == 9


# ═══════════════════════════════════════════════════════════════════════════════
# XSS-S2 — Reflected XSS, alert incorrectly dismissed
#
# cvss=3.4, difficulty=medium, mtta=750s, ttc_expected=23760s, ttc_max=35640s
# alert_severity=low  →  R09 severity gate not met → not_applicable
# no containment_succeeded  →  ttc_factor=0.0, bonus=0
# final_score: clamp(round(30 * 0.0 + 0, 2), 0, 100) = 0
# ═══════════════════════════════════════════════════════════════════════════════

class TestXSSS2:
    def test_final_score(self, s2_result):
        assert s2_result.final_score == 0.0

    def test_verdict(self, s2_result):
        assert s2_result.verdict == "failed"

    def test_penalty_total(self, s2_result):
        # R02(-15) + R04(-25) + R05(-30) = -70
        assert s2_result.penalty_total == -70

    def test_ttc_actual_sec_is_none(self, s2_result):
        # containment_succeeded never happened
        assert s2_result.ttc_actual_sec is None

    def test_ttc_factor_zero(self, s2_result):
        assert s2_result.ttc_factor == pytest.approx(0.0)

    def test_difficulty_bonus_zero(self, s2_result):
        assert s2_result.response_difficulty_bonus == pytest.approx(0.0)

    def test_rule_statuses(self, s2_result):
        st = _statuses(s2_result)
        assert st["XSS-R01"] == "passed"          # inv at 400s < mtta 750s
        assert st["XSS-R02"] == "triggered"       # no incident_confirmed, no dismissal_approved
        assert st["XSS-R03"] == "not_applicable"  # incident_confirmed absent — never got here
        assert st["XSS-R04"] == "triggered"       # containment_initiated absent
        assert st["XSS-R05"] == "triggered"       # containment_succeeded absent
        assert st["XSS-R06"] == "not_applicable"  # containment_succeeded absent — prerequisite unmet
        assert st["XSS-R07"] == "not_applicable"  # eradication_completed absent
        assert st["XSS-R08"] == "not_applicable"  # recovery_validated absent
        assert st["XSS-R09"] == "not_applicable"  # alert_denied present BUT severity=low (below medium)

    def test_exactly_three_triggered(self, s2_result):
        triggered = {r.rule_id for r in s2_result.rules if r.status == "triggered"}
        assert triggered == {"XSS-R02", "XSS-R04", "XSS-R05"}

    def test_penalty_breakdown(self, s2_result):
        pts = _penalties(s2_result)
        assert pts["XSS-R02"] == -15
        assert pts["XSS-R04"] == -25
        assert pts["XSS-R05"] == -30
        non_triggered = {rid: p for rid, p in pts.items()
                         if rid not in {"XSS-R02", "XSS-R04", "XSS-R05"}}
        assert all(p == 0 for p in non_triggered.values()), (
            f"Non-triggered rules should carry 0 penalty: {non_triggered}"
        )

    def test_four_not_applicable(self, s2_result):
        # R03, R06, R07, R08 are all not_applicable (prerequisite chain broken)
        # R09 is not_applicable too (severity gate)
        na = {r.rule_id for r in s2_result.rules if r.status == "not_applicable"}
        assert na == {"XSS-R03", "XSS-R06", "XSS-R07", "XSS-R08", "XSS-R09"}


# ═══════════════════════════════════════════════════════════════════════════════
# XSS-S3 — DOM-Based XSS, delayed detection, full lifecycle
#
# cvss=4.7, difficulty=high, mtta=900s, ttc_expected=19080s, ttc_max=28620s
# containment_succeeded at t=3200s  →  ttc_factor=1.0
# difficulty_bonus: high(3), inv_delay=650 → min(13500/650, 25) = 20.769...
# final_score: clamp(round(100 * 1.0 + 20.769..., 2), 0, 100) = 100
# ═══════════════════════════════════════════════════════════════════════════════

class TestXSSS3:
    def test_final_score(self, s3_result):
        assert s3_result.final_score == 100.0

    def test_verdict(self, s3_result):
        assert s3_result.verdict == "excellent"

    def test_penalty_total(self, s3_result):
        assert s3_result.penalty_total == 0

    def test_ttc_actual_sec(self, s3_result):
        # containment_succeeded at t_offset=3200s
        assert s3_result.ttc_actual_sec == pytest.approx(3200.0)

    def test_ttc_factor(self, s3_result):
        # 3200 ≤ 19080 (ttc_expected) → 1.0
        assert s3_result.ttc_factor == pytest.approx(1.0)

    def test_difficulty_bonus(self, s3_result):
        # difficulty=high → numeric=3; inv_delay=650 → min(4500*3/650, 25)
        expected = min(4500.0 * 3 / 650.0, 25.0)  # 20.76923...
        assert s3_result.response_difficulty_bonus == pytest.approx(expected)

    def test_difficulty_bonus_not_capped(self, s3_result):
        # Confirm the bonus is below the 25-point cap (not just clamped to 100)
        assert s3_result.response_difficulty_bonus < 25.0

    def test_rule_statuses(self, s3_result):
        st = _statuses(s3_result)
        assert st["XSS-R01"] == "passed"          # inv at 650s < mtta 900s
        assert st["XSS-R02"] == "passed"          # incident_confirmed present (1200s)
        assert st["XSS-R03"] == "passed"          # evidence (3040s) before containment_init (3100s)
        assert st["XSS-R04"] == "passed"          # containment_init (3100s) < ttc_max (28620s)
        assert st["XSS-R05"] == "passed"          # containment_succeeded present (3200s)
        assert st["XSS-R06"] == "passed"          # eradication (3500s) after containment_ok (3200s)
        assert st["XSS-R07"] == "passed"          # recovery (3800s) after eradication (3500s)
        assert st["XSS-R08"] == "passed"          # lessons (4100s) after recovery (3800s)
        assert st["XSS-R09"] == "not_applicable"  # no alert_denied

    def test_no_triggered_rules(self, s3_result):
        triggered = [r.rule_id for r in s3_result.rules if r.status == "triggered"]
        assert triggered == [], f"Unexpected triggered rules: {triggered}"

    def test_all_rules_present(self, s3_result):
        assert len(s3_result.rules) == 9


# ═══════════════════════════════════════════════════════════════════════════════
# Regression: difficulty_bonus must not be able to fully mask triggered-rule
# penalties before the final clamp(0,100). Reuses XSS-S1's thresholds with a
# fast, mostly-clean response missing incident_confirmed (R02) and
# lessons_learned_recorded (R08) -- 2 of 7 applicable rules triggered (-20),
# same shape as the live 4-analyst test that surfaced the bug: a +25 raw
# bonus used to fully absorb the -20 penalty and clamp to 100.0, identical to
# a perfect response with the same bonus -- making the penalty invisible.
# ═══════════════════════════════════════════════════════════════════════════════

class TestBonusCannotMaskPenalty:
    @staticmethod
    @pytest.fixture(scope="class")
    def fast_but_incomplete(rule_data):
        incident, events = _build({
            "scenario_id": "XSS-S1",
            "event_log": [
                {"event_type": "alert_raised", "actor_type": "system", "t_offset_sec": 0, "outcome": "detected"},
                {"event_type": "alert_investigation_started", "actor_type": "blue_team", "t_offset_sec": 60, "outcome": "success"},
                # no incident_confirmed -> R02 triggered
                {"event_type": "containment_initiated", "actor_type": "blue_team", "t_offset_sec": 300, "outcome": "success"},
                {"event_type": "containment_succeeded", "actor_type": "blue_team", "t_offset_sec": 360, "outcome": "success"},
                {"event_type": "eradication_completed", "actor_type": "blue_team", "t_offset_sec": 420, "outcome": "success"},
                {"event_type": "recovery_validated", "actor_type": "blue_team", "t_offset_sec": 480, "outcome": "success"},
                # no lessons_learned_recorded -> R08 triggered
            ],
        })
        return score_incident(incident, events, rule_data)

    def test_two_rules_triggered(self, fast_but_incomplete):
        triggered = {r.rule_id for r in fast_but_incomplete.rules if r.status == "triggered"}
        assert triggered == {"XSS-R02", "XSS-R08"}

    def test_penalty_total_is_twenty(self, fast_but_incomplete):
        assert fast_but_incomplete.penalty_total == -20

    def test_raw_bonus_alone_would_have_masked_the_penalty(self, fast_but_incomplete):
        # The pre-fix bug: (100-20)*1.0 + raw_bonus would clamp to 100 here.
        unmasked_score_under_old_formula = max(0.0, min(
            100.0,
            round((100 + fast_but_incomplete.penalty_total) * fast_but_incomplete.ttc_factor
                  + fast_but_incomplete.raw_difficulty_bonus, 2),
        ))
        assert unmasked_score_under_old_formula == 100.0, (
            "fixture no longer reproduces the original masking bug -- adjust offsets"
        )

    def test_final_score_is_no_longer_masked_to_100(self, fast_but_incomplete):
        # The fix: bonus is scaled by compliance ratio (5/7 applicable rules
        # passed), so the penalty now visibly reduces the final score below 100.
        assert fast_but_incomplete.final_score == pytest.approx(97.86)
        assert fast_but_incomplete.final_score < 100.0

    def test_effective_bonus_is_scaled_down_from_raw(self, fast_but_incomplete):
        assert fast_but_incomplete.response_difficulty_bonus < fast_but_incomplete.raw_difficulty_bonus
        expected_ratio = 5 / 7  # 5 passed of 7 applicable (R03, R09 not_applicable)
        assert fast_but_incomplete.response_difficulty_bonus == pytest.approx(
            fast_but_incomplete.raw_difficulty_bonus * expected_ratio
        )

    def test_clean_response_still_scores_100(self, rule_data):
        # Same timings, but WITH incident_confirmed and lessons_learned_recorded
        # added -- compliance_ratio=1.0 -> bonus unscaled -> still clamps to 100.
        # Proves the fix doesn't penalize genuinely clean fast responses.
        incident, events = _build({
            "scenario_id": "XSS-S1",
            "event_log": [
                {"event_type": "alert_raised", "actor_type": "system", "t_offset_sec": 0, "outcome": "detected"},
                {"event_type": "alert_investigation_started", "actor_type": "blue_team", "t_offset_sec": 60, "outcome": "success"},
                {"event_type": "incident_confirmed", "actor_type": "blue_team", "t_offset_sec": 90, "outcome": "success"},
                {"event_type": "evidence_preserved", "actor_type": "blue_team", "t_offset_sec": 150, "outcome": "success"},
                {"event_type": "containment_initiated", "actor_type": "blue_team", "t_offset_sec": 300, "outcome": "success"},
                {"event_type": "containment_succeeded", "actor_type": "blue_team", "t_offset_sec": 360, "outcome": "success"},
                {"event_type": "eradication_completed", "actor_type": "blue_team", "t_offset_sec": 420, "outcome": "success"},
                {"event_type": "recovery_validated", "actor_type": "blue_team", "t_offset_sec": 480, "outcome": "success"},
                {"event_type": "lessons_learned_recorded", "actor_type": "blue_team", "t_offset_sec": 540, "outcome": "success"},
            ],
        })
        result = score_incident(incident, events, rule_data)
        assert result.penalty_total == 0
        assert result.final_score == 100.0
        assert result.response_difficulty_bonus == result.raw_difficulty_bonus
