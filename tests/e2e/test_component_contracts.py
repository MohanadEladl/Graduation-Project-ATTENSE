"""Offline component contract checks for ATTENSE."""
from __future__ import annotations

import importlib
import json
import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]


def _add_path(*parts: str) -> None:
    path = str(ROOT.joinpath(*parts))
    if path not in sys.path:
        sys.path.insert(0, path)


def _clear_modules(prefix: str) -> None:
    for name in list(sys.modules):
        if name == prefix or name.startswith(prefix + "."):
            sys.modules.pop(name, None)


class ComponentContractTests(unittest.TestCase):
    def test_control_api_scenario_catalogue_contract(self):
        _add_path("apps", "control-api")
        _add_path("packages", "attense-core")
        from api.scenarios_router import list_scenarios

        scenarios = list_scenarios()
        self.assertEqual(len(scenarios), 6)
        self.assertEqual([item["attack_id"] for item in scenarios], [f"APP-{idx:02d}" for idx in range(1, 7)])

    def test_watcher_command_classification_contract(self):
        _clear_modules("agent")
        _add_path("apps", "watcher")
        agent = importlib.import_module("agent")

        cases = {
            "cat /var/log/auth.log": "investigation_started",
            "sha256sum /tmp/payload": "evidence_preserved",
            "iptables -A INPUT -s 10.0.0.1 -j DROP": "containment_initiated",
            "systemctl status nginx": "recovery_validated",
            "echo hello": None,
        }
        for command, expected in cases.items():
            self.assertEqual(agent._classify_by_verb(command), expected, command)

    def test_signal_mapper_wazuh_alert_contract(self):
        _clear_modules("app")
        _add_path("apps", "signal-mapper")
        _add_path("apps", "control-api")
        _add_path("packages", "attense-core")
        os.environ["INCIDENT_ID"] = "exercise-incident-001"
        try:
            from app.mapper import map_alert

            event = map_alert({
                "id": "1778258112.30741",
                "timestamp": "2026-03-03T16:25:00.000+0000",
                "rule": {
                    "id": "31106",
                    "level": 7,
                    "description": "Cross-site scripting (XSS) attempt",
                    "groups": ["web", "attack", "xss"],
                },
                "agent": {"id": "001", "name": "sandbox-target", "ip": "172.18.0.2"},
                "location": "/var/log/nginx/access.log",
                "full_log": "GET /index.php?name=<script>alert(1)</script> HTTP/1.1",
                "data": {"srcip": "172.18.0.1"},
            })
        finally:
            os.environ.pop("INCIDENT_ID", None)

        self.assertIsNotNone(event)
        self.assertEqual(event.incident_id, "exercise-incident-001")
        self.assertEqual(event.scenario_id, "APP-01")
        self.assertEqual(event.event_type, "alert_raised")
        self.assertEqual(event.actor_id, "wazuh")
        self.assertEqual(event.metadata["source_event_id"], "1778258112.30741")

    def test_blue_team_health_contract(self):
        _clear_modules("blueteam")
        _add_path("apps", "blue-team-api")
        _add_path("packages", "attense-core")
        from blueteam.main import app

        response = TestClient(app).get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_blue_team_analyst_action_extractor_contract(self):
        _clear_modules("blueteam")
        _add_path("apps", "blue-team-api")
        from blueteam.core.blueactions.analyst_action_extractor import extract_analyst_action

        action = extract_analyst_action({
            "objectType": "case",
            "operation": "create",
            "createdBy": "Alice@lab.local",
            "object": {"tags": ["attense:incident-i1", "APP-01"], "title": "XSS"},
        })
        self.assertEqual(action["event_type"], "investigation_started")
        self.assertEqual(action["analyst_id"], "analyst-alice")
        self.assertEqual(action["incident_id"], "i1")

    def test_red_team_backend_health_contract(self):
        _clear_modules("backend")
        _add_path("apps", "red-team-api")
        from backend.main import app

        response = TestClient(app).get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIs(payload["ok"], True)
        self.assertGreaterEqual(payload["modules"], 1)

    def test_report_scoring_contract(self):
        _add_path("apps", "control-api")
        _add_path("packages", "attense-core")
        from attense_core.evaluation.attack_rules import ATTACK_RULE_DATA_DIR
        from attense_core.models.event import Event
        from attense_core.models.incident import Incident
        from pipeline.scoring_engine import score_incident

        with open(ATTACK_RULE_DATA_DIR / "APP-01-XSS.json", encoding="utf-8") as handle:
            rule_data = json.load(handle)
        scenario = next(item for item in rule_data["scenarios"] if item["scenario_id"] == "XSS-S1")
        t0 = datetime(2025, 1, 1, 9, 0, 0)
        alert_events = {
            "alert_raised",
            "alert_investigation_started",
            "incident_confirmed",
            "alert_denied",
            "incident_ended",
            "dismissal_approved",
        }
        incident = Incident("contract-incident", scenario["scenario_id"])
        events = []
        for index, entry in enumerate(scenario["event_log"]):
            event = Event(
                event_id=f"ev-{index:03d}",
                incident_id="contract-incident",
                scenario_id=scenario["scenario_id"],
                actor_id=entry.get("actor_id", "system"),
                target_id="sandbox-target",
                event_type=entry["event_type"],
                actor_type=entry["actor_type"],
                target_type="alert" if entry["event_type"] in alert_events else "service",
                timestamp=t0 + timedelta(seconds=entry["t_offset_sec"]),
                outcome=entry["outcome"],
                metadata={"detail": entry.get("detail", "")},
            )
            events.append(event)
            incident.apply_event(event)

        result = score_incident(incident, events, rule_data)
        self.assertGreaterEqual(result.final_score, 0)
        self.assertLessEqual(result.final_score, 100)
        self.assertTrue(result.verdict)


if __name__ == "__main__":
    unittest.main()
