"""Unit coverage for Wazuh-alert classification rules."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from app.classifier import classify  # noqa: E402
from app.schema import WazuhAlert  # noqa: E402


def alert(rule_id: str, level: int, description: str = "", groups: list[str] | None = None) -> WazuhAlert:
    return WazuhAlert.from_dict({
        "id": "test-1", "timestamp": "2026-01-01T00:00:00+00:00",
        "rule": {"id": rule_id, "level": level, "description": description, "groups": groups or []},
        "agent": {"id": "001", "name": "target", "ip": "127.0.0.1"},
        "location": "test", "full_log": description, "data": {},
    })


class ClassifierTests(unittest.TestCase):
    def test_exact_rule_id_has_priority(self):
        result = classify(alert("31106", 1, "unrelated", ["generic"]))
        self.assertEqual((result.event_type, result.severity), ("xss", "high"))

    def test_keyword_match_never_reduces_configured_severity(self):
        result = classify(alert("unknown", 12, "command injection"))
        self.assertEqual((result.event_type, result.severity), ("command_injection", "critical"))

    def test_unknown_alert_is_generic_with_level_severity(self):
        result = classify(alert("unknown", 4, "ordinary event"))
        self.assertEqual((result.event_type, result.severity), ("generic", "medium"))
