"""Phase 4 correlation tests.

Exit condition: a complete exercise produces exactly ONE incident and ONE
correct TTD/TTC timeline, with external identifiers (e.g. a Wazuh alert id) kept
separate from the ATTENSE incident_id.

These assert the correlation at the contract + durable-store level, independent
of the producer wiring (the red-team engine and Wazuh mapper changes are tested
in tests/integration/red-team-api/ and tests/integration/signal-mapper/).

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_correlation.py
"""

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from ATTENSE_app.events.standard_event import StandardEvent
from ATTENSE_app.persistence.event_repository import EventRepository

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def event(event_type, minutes, *, incident_id="INC-EX-1", source="red-team",
          actor_type="system", target_type="service", outcome=None,
          source_event_id=None, run_id=None, event_id=None):
    return StandardEvent.model_validate({
        "source": source,
        "event_id": event_id or f"{event_type}-{minutes}",
        "incident_id": incident_id,
        "run_id": run_id,
        "source_event_id": source_event_id,
        "scenario_id": "APP-01",
        "actor_id": "actor-1",
        "actor_type": actor_type,
        "target_id": "target-1",
        "target_type": target_type,
        "event_type": event_type,
        "occurred_at": (T0 + timedelta(minutes=minutes)).isoformat(),
        "outcome": outcome,
        "metadata": {},
    })


class SourceEventIdContractTests(unittest.TestCase):
    def test_source_event_id_is_a_first_class_field(self):
        ev = event("alert_raised", 0, source_event_id="1778258112.30741")
        self.assertEqual(ev.source_event_id, "1778258112.30741")

    def test_promoted_from_metadata(self):
        # A producer (Wazuh mapper) that only sets it in metadata still ends up
        # with it on the field, via StandardEvent's promotion.
        ev = StandardEvent.from_ingest_payload({
            "event_id": "w1",
            "incident_id": "INC-EX-1",
            "scenario_id": "APP-01",
            "actor_id": "wazuh",
            "actor_type": "system",
            "target_id": "agent-1",
            "target_type": "service",
            "event_type": "alert_raised",
            "timestamp": T0.isoformat(),
            "outcome": "detected",
            "metadata": {"source_event_id": "wz-99", "run_id": "run-5"},
        })
        self.assertEqual(ev.source_event_id, "wz-99")
        self.assertEqual(ev.run_id, "run-5")

    def test_round_trips_through_legacy_bridge(self):
        ev = event("alert_raised", 0, source_event_id="wz-1", run_id="run-1")
        self.assertEqual(ev.to_legacy_event().metadata["source_event_id"], "wz-1")
        again = StandardEvent.from_ingest_payload(ev.to_legacy_event_dict())
        self.assertEqual(again.source_event_id, "wz-1")
        self.assertEqual(again.run_id, "run-1")


class CorrelationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.repo = EventRepository(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_one_exercise_is_one_incident_with_correct_ttd(self):
        # Red-team attack at T0 (start/trigger time) and a Wazuh detection 3 min
        # later, both correlated to the SAME exercise incident_id.
        self.repo.append(event("malicious_action_executed", 0, source="red-team", actor_type="red_team", outcome="success"))
        self.repo.append(event("alert_raised", 3, source="signal-store", target_type="alert",
                               outcome="detected", source_event_id="1778258112.30741"))

        # Exactly one incident, not split into two.
        self.assertEqual(self.repo.all_incident_ids(), ["INC-EX-1"])

        proj = self.repo.get_projection("INC-EX-1")
        self.assertEqual(proj.start_time, T0)                       # attack start
        self.assertEqual(proj.detection_time, T0 + timedelta(minutes=3))
        self.assertEqual(proj.ttd_seconds, 180.0)                  # correct, non-zero

    def test_external_id_kept_separate_from_incident_id(self):
        self.repo.append(event("malicious_action_executed", 0, actor_type="red_team"))
        self.repo.append(event("alert_raised", 3, source="signal-store", target_type="alert",
                               outcome="detected", source_event_id="1778258112.30741"))
        alert = [e for e in self.repo.get_events("INC-EX-1")
                 if e.event_type.value == "alert_raised"][0]
        self.assertEqual(alert.incident_id, "INC-EX-1")            # ATTENSE id
        self.assertEqual(alert.source_event_id, "1778258112.30741")  # external id, separate

    def test_source_event_id_survives_restart(self):
        self.repo.append(event("alert_raised", 0, source="signal-store", target_type="alert",
                               outcome="detected", source_event_id="wz-1"))
        reopened = EventRepository(self.dir)
        self.assertEqual(reopened.get_events("INC-EX-1")[0].source_event_id, "wz-1")


if __name__ == "__main__":
    unittest.main()
