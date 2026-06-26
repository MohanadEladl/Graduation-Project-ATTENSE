"""Unit coverage for TheHive webhook-to-analyst-action translation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from blueteam.core.blueactions.analyst_action_extractor import extract_analyst_action  # noqa: E402


class AnalystActionExtractorTests(unittest.TestCase):
    def test_case_creation_starts_an_investigation(self):
        action = extract_analyst_action({
            "objectType": "case", "operation": "create", "createdBy": "Alice@lab.local",
            "object": {"tags": ["attense:incident-i1", "APP-01"], "title": "XSS"},
        })
        self.assertEqual(action["analyst_id"], "analyst-alice")
        self.assertEqual(action["incident_id"], "i1")
        self.assertEqual(action["event_type"], "investigation_started")

    def test_unmapped_webhook_is_ignored(self):
        self.assertIsNone(extract_analyst_action({"objectType": "case", "operation": "delete", "object": {}}))
