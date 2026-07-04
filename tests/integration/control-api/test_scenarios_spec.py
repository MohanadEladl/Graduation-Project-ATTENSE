"""Phase 6 tests: the canonical scenario specs + /api/scenarios.

Proves the consolidation foundation: every scenario loads/validates from its own
versioned file, is reachable through the API, and the canonical specs preserve
the original `scenarios.json` catalogue (so nothing was lost migrating to one
source). Requires pydantic + fastapi (both pinned by attense-app).

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_scenarios_spec.py
"""

import json
import os
import sys
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from ATTENSE_app.scenario_specs import (
    ScenarioSpec,
    get_scenario,
    get_scenario_by_module,
    load_scenarios,
)

EXPECTED_IDS = ["APP-01", "APP-02", "APP-03", "APP-04", "APP-05", "APP-06"]
_LEGACY_CATALOGUE = os.path.join(
    _PKG_ROOT, "ATTENSE_app", "Scenarios", "scenarios.json"
)


class ScenarioLoaderTests(unittest.TestCase):
    def test_all_scenarios_load_and_validate(self):
        specs = load_scenarios()
        self.assertEqual(sorted(specs), EXPECTED_IDS)
        for spec in specs.values():
            self.assertIsInstance(spec, ScenarioSpec)

    def test_each_spec_has_core_fields(self):
        for spec in load_scenarios().values():
            self.assertTrue(spec.name)
            self.assertTrue(spec.module_id)
            self.assertTrue(spec.target_path)
            self.assertTrue(spec.attack_steps)
            self.assertTrue(spec.defense_checkpoints)

    def test_get_scenario(self):
        self.assertEqual(get_scenario("APP-01").name, "Cross-Site Scripting (XSS)")
        self.assertIsNone(get_scenario("APP-99"))

    def test_get_scenario_by_module(self):
        self.assertEqual(get_scenario_by_module("xss").attack_id, "APP-01")
        self.assertEqual(get_scenario_by_module("brute_force").attack_id, "APP-06")
        self.assertIsNone(get_scenario_by_module("nope"))

    def test_module_ids_are_unique(self):
        modules = [s.module_id for s in load_scenarios().values()]
        self.assertEqual(len(modules), len(set(modules)))


class CataloguePreservedTests(unittest.TestCase):
    """The canonical specs must preserve the original scenarios.json catalogue,
    so migrating to one source did not silently change any scenario."""

    @classmethod
    def setUpClass(cls):
        with open(_LEGACY_CATALOGUE, encoding="utf-8") as fh:
            cls.legacy = {
                s["attack_id"]: s
                for s in json.load(fh)["application_based_attack_scenarios"]
            }

    def test_catalogue_fields_match(self):
        for attack_id, legacy in self.legacy.items():
            spec = get_scenario(attack_id)
            self.assertIsNotNone(spec, attack_id)
            self.assertEqual(spec.name, legacy["attack_type"])
            self.assertEqual(spec.description, legacy["description"])
            self.assertEqual(spec.attack_steps, legacy["attack_steps"])
            self.assertEqual(spec.impact, legacy["impact"])
            self.assertEqual(
                spec.defense_checkpoints, legacy["blue_team_evaluation_metrics"]
            )


class ScenarioApiTests(unittest.TestCase):
    def setUp(self):
        from api.scenarios_router import router

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_list_returns_all(self):
        resp = self.client.get("/api/scenarios")
        self.assertEqual(resp.status_code, 200)
        ids = [s["attack_id"] for s in resp.json()]
        self.assertEqual(sorted(ids), EXPECTED_IDS)

    def test_get_one(self):
        resp = self.client.get("/api/scenarios/APP-02")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["name"], "Command Injection")
        self.assertEqual(body["module_id"], "cmd_injection")

    def test_unknown_scenario_404(self):
        self.assertEqual(self.client.get("/api/scenarios/APP-99").status_code, 404)


if __name__ == "__main__":
    unittest.main()
