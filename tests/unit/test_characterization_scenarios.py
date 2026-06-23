"""Characterization snapshot of the scenario catalogue.

Phase 1 of ATTENSE_Refactoring_Optimization_Report.md, item 5: "Capture current
scenario API responses as characterization fixtures." There is no /api/scenarios
endpoint yet; the catalogue lives in ATTENSE_app/Scenarios/scenarios.json and is
duplicated into the frontend / backend (report Redundancy #3). Before Phase 6
consolidates scenarios into one versioned source, pin the current content so the
migration can be proven to preserve it byte-for-byte (modulo JSON normalization).

If this test fails after an intentional scenario edit, regenerate CONTENT_SHA256
from the printed actual hash and update it in the same commit as the data change.

    # from repo root
    py -m unittest tests.unit.test_characterization_scenarios
"""

import hashlib
import json
import os
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SCENARIOS_PATH = os.path.join(
    _REPO_ROOT, "apps", "control-api", "ATTENSE_app", "Scenarios", "scenarios.json"
)

EXPECTED_IDS = ["APP-01", "APP-02", "APP-03", "APP-04", "APP-05", "APP-06"]
REQUIRED_KEYS = {
    "attack_id",
    "attack_type",
    "description",
    "attack_steps",
    "impact",
    "blue_team_evaluation_metrics",
}
# sha256 of json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",",":"))
CONTENT_SHA256 = "a70be4b33e3179c656456bc1509ace9cf27d552ada2779585b54f6f99237c9db"


class ScenarioCatalogueSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_SCENARIOS_PATH, encoding="utf-8") as fh:
            cls.data = json.load(fh)
        cls.scenarios = cls.data["application_based_attack_scenarios"]

    def test_top_level_key(self):
        self.assertIn("application_based_attack_scenarios", self.data)

    def test_scenario_count(self):
        self.assertEqual(len(self.scenarios), 6)

    def test_scenario_ids_and_order(self):
        self.assertEqual([s["attack_id"] for s in self.scenarios], EXPECTED_IDS)

    def test_every_scenario_has_required_keys(self):
        for scenario in self.scenarios:
            self.assertTrue(
                REQUIRED_KEYS.issubset(scenario.keys()),
                msg=f"{scenario.get('attack_id')} missing keys: "
                f"{REQUIRED_KEYS - set(scenario.keys())}",
            )

    def test_content_hash_is_pinned(self):
        normalized = json.dumps(
            self.data, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        actual = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        self.assertEqual(
            actual,
            CONTENT_SHA256,
            msg=f"scenarios.json content changed; actual sha256={actual}",
        )


if __name__ == "__main__":
    unittest.main()
