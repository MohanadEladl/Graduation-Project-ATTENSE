"""Tests for the durable persistence layer + controller dual-write (Phase 3).

Verifies the exit condition: events for one incident form a single ordered,
durable timeline that survives restarts; idempotency by event_id; the projection
matches the legacy in-memory evaluation (dual-write parity, report step 5).

Requires pydantic (StandardEvent). The event store backend is plain JSON
(events.jsonl + incidents.json), so no extra dependency for that.

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_persistence.py
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
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.matrics.metrics import TTC_calculation, TTD_calculation
from ATTENSE_app.Outcomes.outcome import classify_outcome
from ATTENSE_app.persistence.event_repository import EventRepository
from ATTENSE_app.persistence.incident_projection import IncidentProjection

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def make_event(event_type, minutes=0, *, incident_id="INC-1", event_id=None,
               outcome=None, actor_type="system", target_type="service",
               scenario_id="APP-01", source="red-team"):
    return StandardEvent.model_validate({
        "source": source,
        "event_id": event_id or f"{event_type}-{minutes}",
        "incident_id": incident_id,
        "scenario_id": scenario_id,
        "actor_id": "actor-1",
        "actor_type": actor_type,
        "target_id": "target-1",
        "target_type": target_type,
        "event_type": event_type,
        "occurred_at": (T0 + timedelta(minutes=minutes)).isoformat(),
        "outcome": outcome,
        "metadata": {},
    })


LIFECYCLE = [
    make_event("malicious_action_executed", 0, actor_type="red_team"),
    make_event("alert_raised", 2, target_type="alert"),
    make_event("alert_investigation_started", 3, actor_type="blue_team", target_type="alert"),
    make_event("incident_confirmed", 4, actor_type="blue_team", target_type="alert"),
    make_event("containment_initiated", 6, actor_type="blue_team", target_type="host"),
    make_event("containment_succeeded", 9, actor_type="blue_team", target_type="host"),
    make_event("incident_ended", 12, target_type="service"),
]


def _legacy_state(events):
    """Compute incident state the legacy in-memory way, for parity comparison."""
    inc = Incident("INC-1", "APP-01")
    for ev in events:
        inc.apply_event(ev.to_legacy_event())
    ttd = TTD_calculation(inc)
    ttc = TTC_calculation(inc)
    return {
        "status": inc.status,
        "outcome": classify_outcome(inc),
        "ttd": ttd.total_seconds() if ttd else None,
        "ttc": ttc.total_seconds() if ttc else None,
        "failures": inc.containment_failures,
    }


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.repo = EventRepository(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_append_returns_true_and_get_events_is_time_ordered(self):
        # Insert out of chronological order; expect chronological read-back.
        self.assertTrue(self.repo.append(make_event("incident_confirmed", 4)))
        self.assertTrue(self.repo.append(make_event("malicious_action_executed", 0)))
        self.assertTrue(self.repo.append(make_event("alert_raised", 2)))
        times = [e.occurred_at for e in self.repo.get_events("INC-1")]
        self.assertEqual(times, sorted(times))
        self.assertEqual(times[0], T0)

    def test_duplicate_event_id_is_ignored(self):
        ev = make_event("malicious_action_executed", 0, event_id="DUP")
        self.assertTrue(self.repo.append(ev))
        self.assertFalse(self.repo.append(ev))  # same id -> ignored
        self.assertEqual(len(self.repo.get_events("INC-1")), 1)

    def test_duplicate_does_not_double_count_failures(self):
        # The Phase 1 bug: legacy double-counts duplicate failures. The repo
        # dedups by event_id, so the projection counts it once.
        self.repo.append(make_event("containment_failed", 1, event_id="F", actor_type="blue_team"))
        self.repo.append(make_event("containment_failed", 1, event_id="F", actor_type="blue_team"))
        self.assertEqual(self.repo.get_projection("INC-1").containment_failures, 1)
        # distinct ids still accumulate
        self.repo.append(make_event("containment_failed", 2, event_id="F2", actor_type="blue_team"))
        self.assertEqual(self.repo.get_projection("INC-1").containment_failures, 2)

    def test_projection_matches_legacy_full_lifecycle(self):
        for ev in LIFECYCLE:
            self.repo.append(ev)
        proj = self.repo.get_projection("INC-1")
        legacy = _legacy_state(LIFECYCLE)
        self.assertEqual(proj.status, legacy["status"])
        self.assertEqual(proj.status, "ENDED")
        self.assertEqual(proj.outcome, legacy["outcome"])
        self.assertEqual(proj.outcome, "SUCCESS")
        self.assertEqual(proj.ttd_seconds, legacy["ttd"])
        self.assertEqual(proj.ttc_seconds, legacy["ttc"])
        self.assertEqual(proj.ttd_seconds, 120.0)   # 2 min
        self.assertEqual(proj.ttc_seconds, 420.0)    # 7 min

    def test_state_survives_restart(self):
        for ev in LIFECYCLE:
            self.repo.append(ev)
        before = self.repo.get_projection("INC-1")

        # "restart": a fresh repository on the same directory reloads from disk.
        repo2 = EventRepository(self.dir)
        after = repo2.get_projection("INC-1")
        self.assertEqual(after.status, before.status)
        self.assertEqual(after.ttd_seconds, before.ttd_seconds)
        self.assertEqual(len(repo2.get_events("INC-1")), len(LIFECYCLE))
        # And the projection can be rebuilt purely from the durable event log.
        rebuilt = repo2.rebuild_projection("INC-1")
        self.assertEqual(rebuilt.status, before.status)
        self.assertEqual(rebuilt.outcome, before.outcome)


class TransitionAnomalyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.repo = EventRepository(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_ordered_lifecycle_has_no_anomalies(self):
        for ev in LIFECYCLE:
            self.repo.append(ev)
        proj = IncidentProjection.from_events("INC-1", "APP-01", self.repo.get_events("INC-1"))
        self.assertEqual(proj.anomalies, [])

    def test_out_of_order_containment_is_flagged(self):
        # containment_succeeded straight from NOT_STARTED is not an expected step.
        self.repo.append(make_event("containment_succeeded", 5, actor_type="blue_team", target_type="host"))
        self.repo.append(make_event("incident_confirmed", 10, actor_type="blue_team", target_type="alert"))
        proj = IncidentProjection.from_events("INC-1", "APP-01", self.repo.get_events("INC-1"))
        self.assertTrue(proj.anomalies)
        self.assertEqual(proj.anomalies[0]["event_type"], "containment_succeeded")


class ControllerDualWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["ATTENSE_EVENT_STORE_DIR"] = self.tmpdir
        import controller as controller_module
        self.controller = controller_module.AttenseController()

    def tearDown(self):
        os.environ.pop("ATTENSE_EVENT_STORE_DIR", None)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dual_write_projection_matches_in_memory(self):
        for ev in LIFECYCLE:
            self.controller.process_event(ev.to_legacy_event_dict())

        # in-memory (legacy) view
        incident = self.controller.incidents["INC-1"]
        # durable view
        proj = self.controller.event_repository.get_projection("INC-1")

        self.assertEqual(proj.status, incident.status)
        self.assertEqual(proj.status, "ENDED")
        self.assertEqual(proj.outcome, "SUCCESS")
        self.assertEqual(proj.ttd_seconds, 120.0)
        self.assertEqual(proj.ttc_seconds, 420.0)
        self.assertEqual(len(self.controller.event_repository.get_events("INC-1")), len(LIFECYCLE))

    def test_dual_write_dedups_replayed_event(self):
        ev = make_event("malicious_action_executed", 0, event_id="REPLAY", actor_type="red_team")
        payload = ev.to_legacy_event_dict()
        self.controller.process_event(payload)
        self.controller.process_event(payload)  # replay
        # durable store ignored the replay...
        self.assertEqual(len(self.controller.event_repository.get_events("INC-1")), 1)
        # ...while the legacy in-memory incident applied it twice (documented gap)
        self.assertEqual(len(self.controller.incidents["INC-1"].events), 2)


class DurableStoreDisabledTests(unittest.TestCase):
    def test_no_repository_when_env_unset(self):
        os.environ.pop("ATTENSE_EVENT_STORE_DIR", None)
        import controller as controller_module
        ctrl = controller_module.AttenseController()
        self.assertIsNone(ctrl.event_repository)
        # process_event still works with the durable store disabled
        ctrl.process_event(make_event("malicious_action_executed", 0).to_legacy_event_dict())
        self.assertEqual(ctrl.incidents["INC-1"].status, "ACTIVE_UNDETECTED")


if __name__ == "__main__":
    unittest.main()
