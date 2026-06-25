import json
import math
import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = _REPO_ROOT / "apps" / "control-api" / "ATTENSE_app" / "AI" / "Data"
VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R)/"
    r"S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)$"
)


def roundup(value):
    return math.ceil((value - 1e-10) * 10) / 10


def cvss_base_score(vector):
    match = VECTOR_RE.fullmatch(vector)
    if not match:
        raise ValueError(f"Invalid CVSS vector: {vector}")
    av, ac, pr, ui, scope, confidentiality, integrity, availability = match.groups()
    av_weight = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[av]
    ac_weight = {"L": 0.77, "H": 0.44}[ac]
    pr_weight = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }[scope][pr]
    ui_weight = {"N": 0.85, "R": 0.62}[ui]
    impact_weight = {"N": 0.0, "L": 0.22, "H": 0.56}
    isc = 1 - (
        (1 - impact_weight[confidentiality])
        * (1 - impact_weight[integrity])
        * (1 - impact_weight[availability])
    )
    if scope == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight
    raw = impact + exploitability
    return roundup(min(raw, 10) if scope == "U" else min(1.08 * raw, 10))


def first_time(events, event_type):
    event = next((item for item in events if item["event_type"] == event_type), None)
    return event["t_offset_sec"] if event else None


class AttackDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = sorted(DATA_DIR.glob("APP-*.json"))
        cls.documents = [(path, json.loads(path.read_text(encoding="utf-8"))) for path in cls.paths]

    def test_expected_files_and_schema_version(self):
        self.assertEqual(6, len(self.documents))
        self.assertEqual(
            [f"APP-{number:02d}" for number in range(1, 7)],
            [document["attack_id"] for _, document in self.documents],
        )
        for _, document in self.documents:
            self.assertEqual("2.0.0", document["schema_version"])
            self.assertEqual("2026-06-20", document["dataset_metadata"]["last_authoritative_source_review"])
            self.assertRegex(document["owasp"]["category"], r"^A[0-9]{2}:2025$")
            self.assertIn("/Top10/2025/", document["owasp"]["source"])
            self.assertEqual("CVSS v4.0", document["cvss_methodology"]["latest_available_version"])

    def test_cvss_vectors_and_scores(self):
        expected_rationale_prefixes = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                with self.subTest(path=path.name, scenario=scenario["scenario_id"]):
                    self.assertEqual("3.1", scenario["cvss"]["version"])
                    self.assertEqual(
                        scenario["cvss"]["base_score"],
                        cvss_base_score(scenario["cvss"]["vector"]),
                    )
                    rationale_keys = set(scenario["cvss"]["component_rationale"])
                    self.assertEqual(
                        expected_rationale_prefixes,
                        {key.split("_")[0] for key in rationale_keys if key != "formula_trace"},
                    )
                    self.assertTrue(all(":" not in key for key in rationale_keys))

    def test_bonus_formula_is_zero_delay_safe(self):
        expected = "min(4500 * difficulty_numeric / max(investigation_delay_sec, 1), 25)"
        for path, document in self.documents:
            bonus = document["scoring"]["response_difficulty_bonus"]
            self.assertEqual(expected, bonus["formula"], path.name)
            self.assertEqual(25, min(4500 * 4 / max(0, 1), 25))

    def test_known_prose_regressions_are_absent(self):
        serialized = "\n".join(path.read_text(encoding="utf-8") for path, _ in self.documents)
        self.assertNotIn("Plaintext '. Detection", serialized)
        self.assertNotIn("Double extension. php. jpg", serialized)
        self.assertNotIn("alert_denied at Wazuh level 7", serialized)

    def test_thresholds_are_recomputable_and_nonzero(self):
        mtta = {"low": 600, "medium": 750, "high": 900, "very_high": 1200}
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                with self.subTest(path=path.name, scenario=scenario["scenario_id"]):
                    score = scenario["cvss"]["base_score"]
                    expected = max(900, round(3600 * (10 - score)))
                    thresholds = scenario["computed_thresholds"]
                    self.assertEqual(expected, thresholds["ttc_expected_sec"])
                    self.assertEqual(round(expected * 1.5), thresholds["ttc_max_sec"])
                    self.assertGreater(thresholds["ttc_max_sec"] - expected, 0)
                    self.assertEqual(mtta[scenario["detection"]["difficulty"]], thresholds["mtta_threshold_sec"])

    def test_events_are_ordered_and_use_canonical_names(self):
        forbidden = {"investigation_started"}
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                events = scenario["event_log"]
                offsets = [event["t_offset_sec"] for event in events]
                self.assertEqual(sorted(offsets), offsets, (path.name, scenario["scenario_id"]))
                self.assertFalse(forbidden & {event["event_type"] for event in events})
                alert = next(event for event in events if event["event_type"] == "alert_raised")
                self.assertEqual("system", alert["actor_type"])
                self.assertEqual("wazuh", alert["actor_id"])
                declared_alert = scenario["wazuh_alert"]
                self.assertIn(f"rule {declared_alert['rule_id']} ", alert["detail"])
                self.assertIn(f"level {declared_alert['level']} ", alert["detail"])

    def test_wazuh_rules_are_declared(self):
        for path, document in self.documents:
            declared = {
                rule["rule_id"]: "stock" for rule in document["wazuh"]["stock_rules"]
            } | {
                rule["rule_id"]: "custom" for rule in document["wazuh"]["custom_rules"]
            }
            for rule in document["wazuh"]["custom_rules"]:
                self.assertGreaterEqual(int(rule["rule_id"]), 100000)
                self.assertLessEqual(int(rule["rule_id"]), 120000)
            for scenario in document["scenarios"]:
                alert = scenario["wazuh_alert"]
                self.assertIn(alert["rule_id"], declared, (path.name, scenario["scenario_id"]))
                self.assertEqual(declared[alert["rule_id"]], alert["rule_source"])

    def test_mitre_sources_match_ids(self):
        for path, document in self.documents:
            techniques = document["mitre_attack"]["primary"] + document["mitre_attack"]["related"]
            for item in techniques:
                expected = item["technique_id"].replace(".", "/")
                self.assertEqual(f"https://attack.mitre.org/techniques/{expected}/", item["source"], path.name)

    def test_successful_response_lifecycle_is_complete(self):
        required_after_confirmation = [
            "evidence_preserved",
            "containment_initiated",
            "containment_succeeded",
            "eradication_completed",
            "recovery_validated",
            "lessons_learned_recorded",
        ]
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                if scenario["expected_evaluation"]["verdict"] != "excellent":
                    continue
                times = [first_time(scenario["event_log"], kind) for kind in required_after_confirmation]
                self.assertTrue(all(value is not None for value in times), (path.name, scenario["scenario_id"]))
                self.assertEqual(sorted(times), times, (path.name, scenario["scenario_id"]))

    def test_scores_and_verdicts_are_consistent(self):
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                result = scenario["expected_evaluation"]
                self.assertGreaterEqual(result["final_score"], 0)
                self.assertLessEqual(result["final_score"], 100)
                expected_verdict = (
                    "excellent" if result["final_score"] >= 90
                    else "acceptable" if result["final_score"] >= 70
                    else "needs_review" if result["final_score"] >= 50
                    else "failed"
                )
                self.assertEqual(expected_verdict, result["verdict"], (path.name, scenario["scenario_id"]))
                if result["ttc_actual_sec"] is None:
                    self.assertEqual(0, result["ttc_factor"])
                    self.assertEqual(0, result["final_score"])

    def test_no_legacy_schema_fields_remain(self):
        legacy = {"logs", "rules_evaluation", "cvss_vector", "cvss_base_score", "test_assertion"}
        for path, document in self.documents:
            for scenario in document["scenarios"]:
                self.assertFalse(legacy & scenario.keys(), (path.name, scenario["scenario_id"]))


if __name__ == "__main__":
    unittest.main()
