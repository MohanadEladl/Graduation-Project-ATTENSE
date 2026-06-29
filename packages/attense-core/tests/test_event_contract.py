"""Unit coverage for the canonical event contract."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from attense_core.models.standard_event import StandardEvent  # noqa: E402


class StandardEventTests(unittest.TestCase):
    def test_legacy_timestamp_is_accepted_and_normalized_to_utc(self):
        event = StandardEvent.from_ingest_payload({
            "event_id": "e1", "incident_id": "i1", "scenario_id": "APP-01",
            "actor_id": "red-team", "actor_type": "red_team",
            "target_id": "target", "target_type": "service",
            "event_type": "malicious_action_executed", "timestamp": datetime.now(timezone.utc),
        })
        self.assertEqual(event.occurred_at.tzinfo, timezone.utc)

    def test_extra_fields_are_rejected(self):
        with self.assertRaises(Exception):
            StandardEvent.from_ingest_payload({"unexpected": True})
