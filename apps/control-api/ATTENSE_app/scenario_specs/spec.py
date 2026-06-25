# Compatibility shim — canonical home is `attense_core.models.scenario` / `attense_core.scenarios`.
from attense_core.models.scenario import ScenarioSpec  # noqa: F401
from attense_core.scenarios import (  # noqa: F401
    SCENARIO_DIR, get_scenario, get_scenario_by_module, load_scenarios,
)
