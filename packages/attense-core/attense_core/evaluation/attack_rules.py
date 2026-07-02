"""Attack rule fixture loader for scoring and report generation."""
from __future__ import annotations

import json
from pathlib import Path

ATTACK_RULE_DATA_DIR = Path(__file__).parent / "attack_data"
ATTACK_RULE_FILES: dict[str, str] = {
    "APP-01": "APP-01-XSS.json",
    "APP-02": "APP-02-CMDI.json",
    "APP-03": "APP-03-DIR.json",
    "APP-04": "APP-04-FUP.json",
    "APP-05": "APP-05-CSRF.json",
    "APP-06": "APP-06-BA.json",
}


def load_attack_rule_data(scenario_id: str) -> dict:
    filename = ATTACK_RULE_FILES.get(scenario_id)
    if filename is None:
        raise ValueError(
            f"No rule file registered for scenario_id '{scenario_id}'. "
            f"Known IDs: {sorted(ATTACK_RULE_FILES)}"
        )
    path = ATTACK_RULE_DATA_DIR / filename
    if not path.is_file():
        raise ValueError(
            f"Rule file for scenario_id '{scenario_id}' not found on disk: {path}"
        )
    return json.loads(path.read_text(encoding="utf-8"))
