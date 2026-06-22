"""
ATTENSE_app/AI/live_thresholds.py — Live-incident threshold resolver

Provides canonical cvss_base_score and detection_difficulty per attack type
(APP-01 through APP-06) and computes the three thresholds that the scoring
engine needs at runtime, using the same formulas proven correct by the
fixture-based scoring engine tests:

  ttc_expected_sec = max(900, 3600 * (10 - cvss_base_score))
  ttc_max_sec      = ttc_expected_sec * 1.5
  mtta_threshold_sec from difficulty table: low=600, medium=750,
                                             high=900, very_high=1200

Values independently verified against APP-0X-*.json S1 scenario blocks
(cvss.base_score and detection.difficulty) and against each file's
computed_thresholds block.
"""

from __future__ import annotations

CANONICAL_SCENARIOS: dict[str, dict] = {
    "APP-01": {"cvss_base_score": 7.6, "detection_difficulty": "low"},
    "APP-02": {"cvss_base_score": 9.8, "detection_difficulty": "medium"},
    "APP-03": {"cvss_base_score": 7.5, "detection_difficulty": "low"},
    "APP-04": {"cvss_base_score": 8.8, "detection_difficulty": "medium"},
    "APP-05": {"cvss_base_score": 6.5, "detection_difficulty": "medium"},
    "APP-06": {"cvss_base_score": 8.2, "detection_difficulty": "low"},
}

_MTTA_TABLE: dict[str, int] = {
    "low":       600,
    "medium":    750,
    "high":      900,
    "very_high": 1200,
}


def compute_live_thresholds(scenario_id: str) -> dict:
    """
    Return the three scoring thresholds for a live incident identified only
    by its attack-type scenario_id (e.g. "APP-01").

    Parameters
    ----------
    scenario_id : str
        One of "APP-01" through "APP-06".

    Returns
    -------
    dict with keys:
        cvss_base_score     float
        detection_difficulty str   ("low" / "medium" / "high" / "very_high")
        ttc_expected_sec    float
        ttc_max_sec         float
        mtta_threshold_sec  int

    Raises
    ------
    ValueError if scenario_id is not one of the six registered attack types.
    """
    entry = CANONICAL_SCENARIOS.get(scenario_id)
    if entry is None:
        raise ValueError(
            f"No canonical entry for scenario_id '{scenario_id}'. "
            f"Known types: {sorted(CANONICAL_SCENARIOS)}"
        )

    cvss       = entry["cvss_base_score"]
    difficulty = entry["detection_difficulty"]

    ttc_expected = max(900.0, round(3600.0 * (10.0 - cvss), 2))
    ttc_max      = ttc_expected * 1.5
    mtta         = _MTTA_TABLE[difficulty]

    return {
        "cvss_base_score":      cvss,
        "detection_difficulty": difficulty,
        "ttc_expected_sec":     ttc_expected,
        "ttc_max_sec":          ttc_max,
        "mtta_threshold_sec":   mtta,
    }
