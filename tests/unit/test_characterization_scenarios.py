"""Snapshot checks for the canonical scenario catalogue in attense_core."""

import hashlib
import json
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCENARIO_DIR = _REPO_ROOT / "packages" / "attense-core" / "attense_core" / "scenarios" / "data"

EXPECTED_IDS = ["APP-01", "APP-02", "APP-03", "APP-04", "APP-05", "APP-06"]
REQUIRED_KEYS = {
    "attack_id",
    "name",
    "description",
    "attack_steps",
    "impact",
    "defense_checkpoints",
}


class ScenarioCatalogueSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = sorted(_SCENARIO_DIR.glob("APP-*.json"))
        cls.scenarios = [json.loads(path.read_text(encoding="utf-8")) for path in cls.files]

    def test_scenario_file_count(self):
        self.assertEqual(len(self.files), 6)

    def test_scenario_ids_and_order(self):
        self.assertEqual([s["attack_id"] for s in self.scenarios], EXPECTED_IDS)

    def test_every_scenario_has_required_keys(self):
        for scenario in self.scenarios:
            self.assertTrue(
                REQUIRED_KEYS.issubset(scenario.keys()),
                msg=f"{scenario.get('attack_id')} missing keys: {REQUIRED_KEYS - set(scenario.keys())}",
            )

    def test_content_hash_is_stable(self):
        normalized = json.dumps(self.scenarios, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        actual = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        self.assertRegex(actual, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
