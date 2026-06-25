"""Phase 4 correlation tests for the Wazuh signal mapper.

Proves the incident-split fix: a Wazuh detection correlates to the shared
exercise incident_id (INCIDENT_ID env) instead of minting `wazuh-<alert id>`,
and the Wazuh alert id is preserved separately as source_event_id.

    # from repo root (discover, not dotted import -- "signal-mapper" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/signal-mapper -p test_correlation.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/signal-mapper
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_SIGNAL_MAPPER_DIR = os.path.join(_REPO, "apps", "signal-mapper")
for path in (_SIGNAL_MAPPER_DIR, os.path.join(_REPO, "apps", "control-api"), os.path.join(_REPO, "packages", "attense-core")):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.mapper import _resolve_incident_id, _source_event_id, map_alert
from app.schema import WazuhAlert
from ATTENSE_app.events.standard_event import StandardEvent

ALERT = {
    "id": "1778258112.30741",
    "timestamp": "2026-03-03T16:25:00.000+0000",
    "rule": {"id": "31106", "level": 7,
             "description": "Cross-site scripting (XSS) attempt",
             "groups": ["web", "attack", "xss"]},
    "agent": {"id": "001", "name": "sandbox-target", "ip": "172.18.0.2"},
    "location": "/var/log/nginx/access.log",
    "full_log": "GET /index.php?name=<script>alert(1)</script> HTTP/1.1",
    "data": {"srcip": "172.18.0.1"},
}


class ResolveIncidentIdTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("INCIDENT_ID", None)

    def test_uses_shared_exercise_incident_id_when_set(self):
        os.environ["INCIDENT_ID"] = "exercise-incident-001"
        alert = WazuhAlert.from_dict(ALERT)
        self.assertEqual(_resolve_incident_id(alert), "exercise-incident-001")

    def test_falls_back_to_wazuh_id_without_env(self):
        os.environ.pop("INCIDENT_ID", None)
        alert = WazuhAlert.from_dict(ALERT)
        self.assertEqual(_resolve_incident_id(alert), "wazuh-1778258112.30741")

    def test_source_event_id_is_the_wazuh_alert_id(self):
        alert = WazuhAlert.from_dict(ALERT)
        self.assertEqual(_source_event_id(alert), "1778258112.30741")


class MapAlertCorrelationTests(unittest.TestCase):
    def setUp(self):
        os.environ["INCIDENT_ID"] = "exercise-incident-001"

    def tearDown(self):
        os.environ.pop("INCIDENT_ID", None)

    def test_event_correlates_to_exercise_incident_not_a_split(self):
        event = map_alert(ALERT)
        self.assertIsNotNone(event)
        self.assertEqual(event.incident_id, "exercise-incident-001")
        self.assertNotEqual(event.incident_id, "wazuh-1778258112.30741")

    def test_wazuh_alert_id_preserved_as_source_event_id(self):
        event = map_alert(ALERT)
        self.assertEqual(event.metadata["source_event_id"], "1778258112.30741")

    def test_promotes_into_standard_event_contract(self):
        # The mapped legacy Event, run through the canonical contract, exposes
        # source_event_id as a first-class field separate from incident_id.
        event = map_alert(ALERT)
        std = StandardEvent.from_ingest_payload(event.to_dict())
        self.assertEqual(std.incident_id, "exercise-incident-001")
        self.assertEqual(std.source_event_id, "1778258112.30741")


if __name__ == "__main__":
    unittest.main()
