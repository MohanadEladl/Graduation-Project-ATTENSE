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
    response_difficulty_bonus: float    # the EFFECTIVE bonus actually applied
                                         # (raw bonus * compliance_ratio -- see
                                         # _compliance_ratio below)
    raw_difficulty_bonus: float         # the bonus before compliance scaling,
                                         # used to derive each member's own
                                         # effective bonus in score_members()
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


def _compliance_ratio(rules: list[RuleResult]) -> float:
    """Fraction of APPLICABLE rules (excluding not_applicable) that passed.

    Used to scale response_difficulty_bonus so a fast-but-incomplete response
    can no longer fully mask triggered-rule penalties: previously the bonus
    (up to +25) was added after the penalty and before the final clamp(0,100),
    so e.g. a -20 penalty plus a +25 bonus both clamped to the same 100 as a
    perfect response with the same bonus -- the penalty became invisible in
    the headline score even though it's still listed in the rule breakdown.
    Scaling the bonus by how much of the response was actually compliant
    keeps it as a genuine speed/skill reward without letting it erase process
    gaps. 1.0 when there are no applicable rules (nothing could have failed).
    """
    applicable = [r for r in rules if r.status != "not_applicable"]
    if not applicable:
        return 1.0
    passed = sum(1 for r in applicable if r.status == "passed")
    return passed / len(applicable)


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
    # Raw bonus is scaled by how many of the APPLICABLE rules actually passed
    # (see _compliance_ratio) so a triggered rule's penalty can't be fully
    # masked by a large speed/difficulty bonus before the final clamp.
    raw_bonus = _compute_difficulty_bonus(
        idx.get("containment_succeeded"),
        difficulty,
        idx.get("alert_investigation_started"),
    )
    compliance_ratio = _compliance_ratio(rule_results)
    bonus = raw_bonus * compliance_ratio

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
        raw_difficulty_bonus      = raw_bonus,
        rules                     = rule_results,
    )


# ── Per-member scoring ───────────────────────────────────────────────────────
#
# The 9 rules are evaluated against the whole incident timeline above -- they
# describe one shared incident lifecycle, not one person's. To produce a fair
# personal scorecard per analyst, we reuse that same whole-team evaluation
# (so timing/ordering checks see the real, complete timeline) and then
# re-attribute each rule's outcome by WHO performed its qualifying action:
#
#   - this analyst performed it      -> keep the team-wide status/penalty
#   - a teammate performed it        -> not_applicable for this analyst
#   - nobody performed it on the team -> not_applicable for everyone
#     (a step the whole team skipped isn't one person's personal failure)
#
# TTC factor and difficulty bonus are inherently incident-level (how fast the
# TEAM closed the incident, not one person), so every member's score applies
# the SAME team-wide ttc_factor/response_difficulty_bonus on top of their own
# personalized penalty_total.

# rule suffix -> the event_type whose first-occurrence actor "owns" that
# rule's outcome. R02 is handled separately (confirmed OR dismissal, same
# priority order _r02 itself uses).
_RULE_RESPONSIBLE_EVENT: dict[str, str] = {
    "R01": "alert_investigation_started",
    "R03": "evidence_preserved",
    "R04": "containment_initiated",
    "R05": "containment_succeeded",
    "R06": "eradication_completed",
    "R07": "recovery_validated",
    "R08": "lessons_learned_recorded",
    "R09": "alert_denied",
}


def _build_actor_index(events: list[Event]) -> dict[str, str]:
    """First-occurrence actor_id per event_type -- parallel to
    _build_event_index, used to attribute which analyst's action satisfied
    (or triggered) each rule."""
    index: dict[str, str] = {}
    for ev in events:
        if ev.event_type not in index:
            index[ev.event_type] = ev.actor_id
    return index


def _responsible_actor(suffix: str, idx_actor: dict[str, str]) -> Optional[str]:
    """The actor_id who owns rule *suffix*'s outcome, or None if no one on
    the team performed the qualifying action at all."""
    if suffix == "R02":
        return idx_actor.get("incident_confirmed") or idx_actor.get("dismissal_approved")
    event_type = _RULE_RESPONSIBLE_EVENT.get(suffix)
    return idx_actor.get(event_type) if event_type else None


def score_members(
    incident: Incident,
    events: list[Event],
    rule_data: dict,
    scoring_started_at: Optional[datetime] = None,
) -> dict[str, ScoringResult]:
    """
    Score each individual Blue Team analyst's personal contribution to the
    incident response. See module note above for the attribution rules.

    Returns {} if the incident has no blue_team-actor events.
    """
    team_result = score_incident(incident, events, rule_data, scoring_started_at)
    idx_actor = _build_actor_index(events)

    members = sorted({ev.actor_id for ev in events if ev.actor_type == "blue_team"})
    if not members:
        return {}

    verdict_bands = rule_data["scoring"]["verdict_bands"]

    results: dict[str, ScoringResult] = {}
    for member in members:
        member_rules: list[RuleResult] = []
        penalty_total = 0

        for rule in team_result.rules:
            if rule.status == "not_applicable":
                member_rules.append(rule)
                continue

            suffix = rule.rule_id.split("-")[-1]
            owner = _responsible_actor(suffix, idx_actor)

            if owner == member:
                member_rules.append(rule)
                penalty_total += rule.penalty_points
            else:
                attribution = f"performed by {owner}" if owner else "not performed by anyone on the team"
                member_rules.append(RuleResult(
                    rule_id        = rule.rule_id,
                    description    = rule.description,
                    penalty_points = 0,
                    status         = "not_applicable",
                    evidence       = [f"Not this analyst's action ({attribution})."],
                ))

        # This member's OWN bonus, scaled by THEIR OWN compliance ratio (rules
        # they personally own and passed, out of rules they personally own and
        # were applicable) -- not the team's. A member who did everything asked
        # of them keeps their full bonus even if a teammate triggered a rule
        # elsewhere; a member who personally triggers an owned rule sees their
        # own bonus shrink, same fix as score_incident(), applied per-person.
        member_compliance = _compliance_ratio(member_rules)
        member_bonus = team_result.raw_difficulty_bonus * member_compliance

        raw   = (100 + penalty_total) * team_result.ttc_factor + member_bonus
        score = max(0.0, min(100.0, round(raw, 2)))

        results[member] = ScoringResult(
            final_score               = score,
            verdict                   = _determine_verdict(score, verdict_bands),
            penalty_total             = penalty_total,
            ttc_factor                = team_result.ttc_factor,
            ttc_actual_sec            = team_result.ttc_actual_sec,
            response_difficulty_bonus = member_bonus,
            raw_difficulty_bonus      = team_result.raw_difficulty_bonus,
            rules                     = member_rules,
        )

    return results
