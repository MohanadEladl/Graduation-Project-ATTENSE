"""
pipeline/scoring_engine.py — Incident scoring engine

Evaluates a completed incident against the 9 response rules defined in an
attack-scenario JSON file (schema v2.0.0) and returns a ScoringResult.

Public API
----------
score_incident(incident, events, rule_data) -> ScoringResult

    incident  — Incident object (provides scenario_id for scenario lookup)
    events    — timestamp-ordered list of Event objects for this incident
    rule_data — full attack JSON dict (e.g. APP-01-XSS.json loaded as dict)
                caller handles file I/O; this function is pure

Logic is derived from the manual trace of XSS-S1 / XSS-S2 / XSS-S3 and
verified against those scenarios' expected_evaluation blocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional

from attense_core.models.event import Event
from attense_core.models.incident import Incident

# ── Types ──────────────────────────────────────────────────────────────────────

RuleStatus = Literal["triggered", "passed", "not_applicable"]

_SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "very_high": 3,
}

_DIFFICULTY_NUMERIC: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "very_high": 4,
}


@dataclass
class RuleResult:
    rule_id: str
    description: str
    penalty_points: int   # applied penalty: negative when triggered, 0 otherwise
    status: RuleStatus
    evidence: list[str] = field(default_factory=list)


@dataclass
class ScoringResult:
    final_score: float
    verdict: str
    penalty_total: int
    ttc_factor: float
    ttc_actual_sec: Optional[float]
    response_difficulty_bonus: float
    rules: list[RuleResult]


# ── Event index ────────────────────────────────────────────────────────────────

def _build_event_index(t0: datetime, events: list[Event]) -> dict[str, float]:
    """
    First-occurrence offset (seconds from t0) per event_type.
    Absent event types are simply not in the dict; callers use .get() → None.
    """
    index: dict[str, float] = {}
    for ev in events:
        if ev.event_type not in index:
            index[ev.event_type] = (ev.timestamp - t0).total_seconds()
    return index


# ── Intermediate result ────────────────────────────────────────────────────────

@dataclass
class _Check:
    status: RuleStatus
    evidence: list[str]


# ── Rule functions (R01–R09) ───────────────────────────────────────────────────
# Each receives only the offsets and thresholds it needs and returns a _Check.
# "not_applicable" means the rule's prerequisite event was never present,
# so the rule neither passed nor failed — the response never reached that phase.

def _r01(inv_offset: Optional[float], mtta_threshold: float) -> _Check:
    """Alert triage started within the difficulty-adjusted MTTA threshold."""
    if inv_offset is None:
        return _Check("triggered", ["alert_investigation_started is absent"])
    if inv_offset > mtta_threshold:
        return _Check(
            "triggered",
            [
                f"alert_investigation_started at t={inv_offset:.0f}s"
                f" exceeded mtta_threshold={mtta_threshold:.0f}s"
                f" (late by {inv_offset - mtta_threshold:.0f}s)",
            ],
        )
    return _Check(
        "passed",
        [
            f"alert_investigation_started at t={inv_offset:.0f}s"
            f" within mtta_threshold={mtta_threshold:.0f}s",
        ],
    )


def _r02(
    confirmed_offset: Optional[float],
    dismissal_offset: Optional[float],
) -> _Check:
    """Incident assessed and confirmed or formally dismissed."""
    if confirmed_offset is not None:
        return _Check("passed", [f"incident_confirmed at t={confirmed_offset:.0f}s"])
    if dismissal_offset is not None:
        return _Check("passed", [f"dismissal_approved at t={dismissal_offset:.0f}s"])
    return _Check(
        "triggered",
        ["neither incident_confirmed nor dismissal_approved is present"],
    )


def _r03(
    confirmed_offset: Optional[float],
    evidence_offset: Optional[float],
    containment_init_offset: Optional[float],
) -> _Check:
    """Relevant evidence preserved before destructive containment."""
    if confirmed_offset is None:
        return _Check(
            "not_applicable",
            ["incident_confirmed absent — rule does not apply"],
        )
    if evidence_offset is None:
        return _Check(
            "triggered",
            ["incident_confirmed present but evidence_preserved is absent"],
        )
    if (
        containment_init_offset is not None
        and evidence_offset > containment_init_offset
    ):
        return _Check(
            "triggered",
            [
                f"evidence_preserved at t={evidence_offset:.0f}s is after"
                f" containment_initiated at t={containment_init_offset:.0f}s",
            ],
        )
    suffix = (
        f"before containment_initiated at t={containment_init_offset:.0f}s"
        if containment_init_offset is not None
        else "(no containment initiated — ordering check skipped)"
    )
    return _Check(
        "passed",
        [f"evidence_preserved at t={evidence_offset:.0f}s {suffix}"],
    )


def _r04(containment_init_offset: Optional[float], ttc_max: float) -> _Check:
    """Containment initiated before TTC maximum."""
    if containment_init_offset is None:
        return _Check("triggered", ["containment_initiated is absent"])
    if containment_init_offset > ttc_max:
        return _Check(
            "triggered",
            [
                f"containment_initiated at t={containment_init_offset:.0f}s"
                f" exceeded ttc_max={ttc_max:.0f}s"
                f" (late by {containment_init_offset - ttc_max:.0f}s)",
            ],
        )
    return _Check(
        "passed",
        [
            f"containment_initiated at t={containment_init_offset:.0f}s"
            f" within ttc_max={ttc_max:.0f}s",
        ],
    )


def _r05(containment_ok_offset: Optional[float]) -> _Check:
    """Containment succeeded."""
    if containment_ok_offset is None:
        return _Check("triggered", ["containment_succeeded is absent"])
    return _Check(
        "passed",
        [f"containment_succeeded at t={containment_ok_offset:.0f}s"],
    )


def _r06(
    containment_ok_offset: Optional[float],
    eradication_offset: Optional[float],
) -> _Check:
    """Root cause eradicated after containment."""
    if containment_ok_offset is None:
        return _Check(
            "not_applicable",
            ["containment_succeeded absent — rule does not apply"],
        )
    if eradication_offset is None:
        return _Check(
            "triggered",
            ["containment_succeeded present but eradication_completed is absent"],
        )
    if eradication_offset < containment_ok_offset:
        return _Check(
            "triggered",
            [
                f"eradication_completed at t={eradication_offset:.0f}s is before"
                f" containment_succeeded at t={containment_ok_offset:.0f}s (out of order)",
            ],
        )
    return _Check(
        "passed",
        [
            f"eradication_completed at t={eradication_offset:.0f}s"
            f" after containment_succeeded at t={containment_ok_offset:.0f}s",
        ],
    )


def _r07(
    eradication_offset: Optional[float],
    recovery_offset: Optional[float],
) -> _Check:
    """Recovery validated before normal operation resumed."""
    if eradication_offset is None:
        return _Check(
            "not_applicable",
            ["eradication_completed absent — rule does not apply"],
        )
    if recovery_offset is None:
        return _Check(
            "triggered",
            ["eradication_completed present but recovery_validated is absent"],
        )
    if recovery_offset < eradication_offset:
        return _Check(
            "triggered",
            [
                f"recovery_validated at t={recovery_offset:.0f}s is before"
                f" eradication_completed at t={eradication_offset:.0f}s (out of order)",
            ],
        )
    return _Check(
        "passed",
        [
            f"recovery_validated at t={recovery_offset:.0f}s"
            f" after eradication_completed at t={eradication_offset:.0f}s",
        ],
    )


def _r08(
    recovery_offset: Optional[float],
    lessons_offset: Optional[float],
) -> _Check:
    """Lessons learned and improvement actions recorded."""
    if recovery_offset is None:
        return _Check(
            "not_applicable",
            ["recovery_validated absent — rule does not apply"],
        )
    if lessons_offset is None:
        return _Check(
            "triggered",
            ["recovery_validated present but lessons_learned_recorded is absent"],
        )
    if lessons_offset < recovery_offset:
        return _Check(
            "triggered",
            [
                f"lessons_learned_recorded at t={lessons_offset:.0f}s is before"
                f" recovery_validated at t={recovery_offset:.0f}s (out of order)",
            ],
        )
    return _Check(
        "passed",
        [
            f"lessons_learned_recorded at t={lessons_offset:.0f}s"
            f" after recovery_validated at t={recovery_offset:.0f}s",
        ],
    )


def _r09(
    denied_offset: Optional[float],
    alert_severity: str,
    dismissal_offset: Optional[float],
) -> _Check:
    """Medium-or-higher alerts not denied without documented approval."""
    if denied_offset is None:
        return _Check("not_applicable", ["alert_denied absent — rule does not apply"])
    if _SEVERITY_RANK.get(alert_severity, 0) < _SEVERITY_RANK["medium"]:
        return _Check(
            "not_applicable",
            [
                f"alert_severity='{alert_severity}' is below medium"
                " — severity gate not met, rule does not apply",
            ],
        )
    if dismissal_offset is not None and dismissal_offset <= denied_offset:
        return _Check(
            "passed",
            [
                f"dismissal_approved at t={dismissal_offset:.0f}s"
                f" preceded alert_denied at t={denied_offset:.0f}s",
            ],
        )
    return _Check(
        "triggered",
        [
            f"alert_denied at t={denied_offset:.0f}s for severity='{alert_severity}'"
            " without a preceding dismissal_approved",
        ],
    )


# ── Rule dispatcher ────────────────────────────────────────────────────────────

def _dispatch(
    suffix: str,
    idx: dict[str, float],
    mtta_threshold: float,
    ttc_max: float,
    alert_severity: str,
) -> _Check:
    """Route a rule ID suffix (e.g. 'R01') to its check function."""
    inv       = idx.get("alert_investigation_started")
    conf      = idx.get("incident_confirmed")
    dismissal = idx.get("dismissal_approved")
    evid      = idx.get("evidence_preserved")
    cont_in   = idx.get("containment_initiated")
    cont_ok   = idx.get("containment_succeeded")
    erad      = idx.get("eradication_completed")
    recovery  = idx.get("recovery_validated")
    lessons   = idx.get("lessons_learned_recorded")
    denied    = idx.get("alert_denied")

    if suffix == "R01":
        return _r01(inv, mtta_threshold)
    if suffix == "R02":
        return _r02(conf, dismissal)
    if suffix == "R03":
        return _r03(conf, evid, cont_in)
    if suffix == "R04":
        return _r04(cont_in, ttc_max)
    if suffix == "R05":
        return _r05(cont_ok)
    if suffix == "R06":
        return _r06(cont_ok, erad)
    if suffix == "R07":
        return _r07(erad, recovery)
    if suffix == "R08":
        return _r08(recovery, lessons)
    if suffix == "R09":
        return _r09(denied, alert_severity, dismissal)
    raise ValueError(f"Unknown rule suffix: {suffix!r}")


# ── Scoring helpers ────────────────────────────────────────────────────────────

def _compute_ttc_factor(
    ttc_actual: Optional[float],
    ttc_expected: float,
    ttc_max: float,
) -> float:
    """
    1.0  — containment_succeeded at or before ttc_expected
    linear decay — between ttc_expected and ttc_max
    0.0  — containment absent, or after ttc_max
    """
    if ttc_actual is None or ttc_actual > ttc_max:
        return 0.0
    if ttc_actual <= ttc_expected:
        return 1.0
    return (ttc_max - ttc_actual) / (ttc_max - ttc_expected)


def _compute_difficulty_bonus(
    containment_ok_offset: Optional[float],
    difficulty: str,
    inv_offset: Optional[float],
) -> float:
    """
    min(4500 * difficulty_numeric / max(investigation_delay_sec, 1), 25)
    0.0 when containment_succeeded is absent.
    """
    if containment_ok_offset is None:
        return 0.0
    numeric = _DIFFICULTY_NUMERIC.get(difficulty, 1)
    delay = max(inv_offset if inv_offset is not None else 0.0, 1.0)
    return min(4500.0 * numeric / delay, 25.0)


def _determine_verdict(score: float, verdict_bands: dict) -> str:
    for band_name, bounds in verdict_bands.items():
        if bounds["min"] <= score <= bounds["max"]:
            return band_name
    return "failed"


# ── Public entry point ─────────────────────────────────────────────────────────

def score_incident(
    incident: Incident,
    events: list[Event],
    rule_data: dict,
    scoring_started_at: Optional[datetime] = None,
) -> ScoringResult:
    """
    Score an incident against the rules in rule_data.

    Parameters
    ----------
    incident  : Incident — provides scenario_id for scenario lookup
    events    : list[Event] — timestamp-ordered events for this incident
    rule_data : dict — full attack JSON (e.g. APP-01-XSS.json); no file I/O here

    Returns
    -------
    ScoringResult with final_score, verdict, penalty_total, ttc_factor,
    response_difficulty_bonus, and per-rule status + evidence.
    """
    # ── Locate scenario ───────────────────────────────────────────────────────
    scenario = next(
        (s for s in rule_data.get("scenarios", []) if s["scenario_id"] == incident.scenario_id),
        None,
    )
    if scenario is None:
        available = [s["scenario_id"] for s in rule_data.get("scenarios", [])]
        raise ValueError(
            f"scenario_id '{incident.scenario_id}' not found in rule_data"
            f" (available: {available})"
        )

    thresholds     = scenario["computed_thresholds"]
    mtta_threshold = float(thresholds["mtta_threshold_sec"])
    ttc_expected   = float(thresholds["ttc_expected_sec"])
    ttc_max        = float(thresholds["ttc_max_sec"])
    alert_severity = scenario["alert_severity"]
    difficulty     = scenario["detection"]["difficulty"]
    verdict_bands  = rule_data["scoring"]["verdict_bands"]

    # ── t0 = first alert_raised event ────────────────────────────────────────
    t0_event = next((e for e in events if e.event_type == "alert_raised"), None)
    if scoring_started_at is not None:
        t0 = scoring_started_at
    elif t0_event is not None:
        t0 = t0_event.timestamp
    elif incident.detection_time is not None:
        t0 = incident.detection_time
    else:
        t0 = min(e.timestamp for e in events)

    idx = _build_event_index(t0, events)

    # ── Evaluate rules ────────────────────────────────────────────────────────
    rule_results: list[RuleResult] = []
    penalty_total = 0

    for rule_def in rule_data["incident_response_rules"]:
        rule_id  = rule_def["id"]
        max_pts  = rule_def["penalty_points"]   # always negative in schema
        suffix   = rule_id.split("-")[-1]        # "XSS-R01" → "R01"

        check   = _dispatch(suffix, idx, mtta_threshold, ttc_max, alert_severity)
        applied = max_pts if check.status == "triggered" else 0
        penalty_total += applied

        rule_results.append(
            RuleResult(
                rule_id       = rule_id,
                description   = rule_def["description"],
                penalty_points = applied,
                status        = check.status,
                evidence      = check.evidence,
            )
        )

    # ── TTC factor ────────────────────────────────────────────────────────────
    ttc_actual = idx.get("containment_succeeded")
    ttc_factor = _compute_ttc_factor(ttc_actual, ttc_expected, ttc_max)

    # ── Difficulty bonus ──────────────────────────────────────────────────────
    bonus = _compute_difficulty_bonus(
        idx.get("containment_succeeded"),
        difficulty,
        idx.get("alert_investigation_started"),
    )

    # ── Final score: clamp(round((100 + penalty) * ttc_factor + bonus, 2), 0, 100)
    raw   = (100 + penalty_total) * ttc_factor + bonus
    score = max(0.0, min(100.0, round(raw, 2)))

    return ScoringResult(
        final_score               = score,
        verdict                   = _determine_verdict(score, verdict_bands),
        penalty_total             = penalty_total,
        ttc_factor                = ttc_factor,
        ttc_actual_sec            = ttc_actual,
        response_difficulty_bonus = bonus,
        rules                     = rule_results,
    )
