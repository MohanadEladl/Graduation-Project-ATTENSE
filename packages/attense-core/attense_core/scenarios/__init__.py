"""attense_core.scenarios — canonical per-scenario specs + loader."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

from attense_core.models.scenario import ScenarioSpec

SCENARIO_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def load_scenarios() -> Dict[str, ScenarioSpec]:
    specs: Dict[str, ScenarioSpec] = {}
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        spec = ScenarioSpec.model_validate_json(path.read_text(encoding="utf-8"))
        specs[spec.attack_id] = spec
    return specs


def get_scenario(attack_id: str) -> Optional[ScenarioSpec]:
    return load_scenarios().get(attack_id)


def get_scenario_by_module(module_id: str) -> Optional[ScenarioSpec]:
    for spec in load_scenarios().values():
        if spec.module_id == module_id:
            return spec
    return None


__all__ = ["SCENARIO_DIR", "ScenarioSpec", "load_scenarios", "get_scenario", "get_scenario_by_module"]
