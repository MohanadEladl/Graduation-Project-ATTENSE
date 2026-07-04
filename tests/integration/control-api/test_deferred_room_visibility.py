"""Regression tests for deferred Blue Team room visibility.

Before this fix, `ensure_room_for_incident` fired unconditionally on the very
first `malicious_action_executed` event - the Blue Team room appeared
mid-attack, with no gating on the red-team learner actually finishing. Now:

  * `controller.process_event(...)` still runs for every event (attack events
    keep landing durably and updating the in-memory Incident projection the
    moment they happen).
  * Room creation/surfacing (`room_manager.ensure_room_for_incident`) is
    gated on `event_type == "mission_finished"` instead.
  * The room's `attack_started_at` is sourced from the incident's real first
    attack timestamp (`controller.incidents[incident_id].start_time`), not
    `_now_iso()` at room-creation time (which would otherwise wrongly stamp
    the finish time as the attack start).
  * `rooms_router.py`'s `GET /{room_id}` uses the same scored
    (`run_bridge`-backed) report helper as `incidents_router.py`'s
    `/api/incidents/{id}/report`, instead of the bare unscored
    `generate_report()`.

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_deferred_room_visibility.py
"""

import os
import sys
import types
import unittest
from datetime import datetime, timezone

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from attense_core.models.standard_event import StandardEvent  # noqa: E402
from core import room_manager  # noqa: E402
from api import incidents_router  # noqa: E402


def _event(event_type: str, **overrides) -> StandardEvent:
    payload = {
        "event_id": "E1",
        "incident_id": "INC-deferred",
        "scenario_id": "APP-01",
        "actor_id": "redteam-operator",
        "actor_type": "red_team",
        "target_id": "http://target-agent",
        "target_type": "service",
        "event_type": event_type,
        "occurred_at": "2026-01-01T10:00:00+00:00",
        "outcome": "success",
        "metadata": {},
    }
    payload.update(overrides)
    return StandardEvent.model_validate(payload)


class _StubIncident:
    def __init__(self, start_time=None):
        self.start_time = start_time


class _StubController:
    def __init__(self):
        self.processed = []
        self.incidents = {}

    def process_event(self, event_dict):
        self.processed.append(event_dict)


class IngestEventRoomGatingTests(unittest.TestCase):
    def setUp(self):
        self._orig_main_module = sys.modules.get("main")
        self.controller = _StubController()
        fake_main = types.ModuleType("main")
        fake_main.controller = self.controller
        sys.modules["main"] = fake_main

        self._orig_ensure_room = room_manager.ensure_room_for_incident
        self.ensure_room_calls = []

        def _fake_ensure_room(incident_id, scenario_id, attack_started_at=None):
            self.ensure_room_calls.append((incident_id, scenario_id, attack_started_at))
            return {"room_id": "fake-room"}

        room_manager.ensure_room_for_incident = _fake_ensure_room

    def tearDown(self):
        room_manager.ensure_room_for_incident = self._orig_ensure_room
        if self._orig_main_module is not None:
            sys.modules["main"] = self._orig_main_module
        else:
            sys.modules.pop("main", None)

    def test_malicious_action_executed_lands_durably_but_creates_no_room(self):
        ev = _event("malicious_action_executed")

        result = incidents_router.ingest_event(ev, _auth=None)

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(self.controller.processed), 1)  # still landed durably
        self.assertEqual(self.ensure_room_calls, [])  # but no room surfaced yet

    def test_mission_finished_creates_the_room(self):
        ev = _event("mission_finished")

        incidents_router.ingest_event(ev, _auth=None)

        self.assertEqual(len(self.ensure_room_calls), 1)
        incident_id, scenario_id, _attack_started_at = self.ensure_room_calls[0]
        self.assertEqual(incident_id, "INC-deferred")
        self.assertEqual(scenario_id, "APP-01")

    def test_mission_finished_anchors_attack_started_at_to_the_real_attack_start(self):
        # The incident's start_time was set earlier by a real attack event
        # (as Incident.apply_event does for malicious_action_executed) - the
        # finish event must NOT overwrite it with "now".
        t0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
        self.controller.incidents["INC-deferred"] = _StubIncident(start_time=t0)

        ev = _event("mission_finished", occurred_at="2026-01-01T10:30:00+00:00")
        incidents_router.ingest_event(ev, _auth=None)

        _incident_id, _scenario_id, attack_started_at = self.ensure_room_calls[0]
        self.assertEqual(attack_started_at, t0.isoformat())
        self.assertNotEqual(attack_started_at, "2026-01-01T10:30:00+00:00")

    def test_mission_finished_with_no_known_incident_passes_none(self):
        # No prior attack event ever landed for this incident (edge case) -
        # ensure_room_for_incident's own _now_iso() fallback takes over.
        ev = _event("mission_finished")
        incidents_router.ingest_event(ev, _auth=None)

        _incident_id, _scenario_id, attack_started_at = self.ensure_room_calls[0]
        self.assertIsNone(attack_started_at)

    def test_room_creation_failure_does_not_break_event_ingestion(self):
        def _boom(incident_id, scenario_id, attack_started_at=None):
            raise RuntimeError("company_store unreachable")

        room_manager.ensure_room_for_incident = _boom

        ev = _event("mission_finished")
        try:
            result = incidents_router.ingest_event(ev, _auth=None)
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"ingest_event must be best-effort around room creation, raised: {exc}")
        self.assertEqual(result["status"], "accepted")

    def test_other_event_types_also_create_no_room(self):
        for event_type in ("alert_raised", "incident_confirmed", "containment_succeeded"):
            with self.subTest(event_type=event_type):
                self.ensure_room_calls.clear()
                ev = _event(event_type)
                incidents_router.ingest_event(ev, _auth=None)
                self.assertEqual(self.ensure_room_calls, [])


class EnsureRoomForIncidentTimestampTests(unittest.TestCase):
    """room_manager.ensure_room_for_incident itself: the attack_started_at
    passthrough, independent of the router-level gating tested above."""

    def setUp(self):
        self._orig_find_room = room_manager.find_room_for_incident
        self._orig_save_room = room_manager._save_room
        self._orig_ensure_company = room_manager.company_store.ensure_exercise_company
        self.saved_rooms = []

        room_manager.find_room_for_incident = lambda incident_id: None
        room_manager._save_room = lambda room: self.saved_rooms.append(room)
        room_manager.company_store.ensure_exercise_company = lambda: {"id": "company-1"}

    def tearDown(self):
        room_manager.find_room_for_incident = self._orig_find_room
        room_manager._save_room = self._orig_save_room
        room_manager.company_store.ensure_exercise_company = self._orig_ensure_company

    def test_explicit_attack_started_at_is_used_verbatim(self):
        room = room_manager.ensure_room_for_incident(
            "INC-1", "APP-01", attack_started_at="2026-01-01T09:00:00+00:00",
        )
        self.assertEqual(room["attack_started_at"], "2026-01-01T09:00:00+00:00")
        self.assertEqual(room["exercise_mode"], "deferred")

    def test_missing_attack_started_at_falls_back_to_now(self):
        room = room_manager.ensure_room_for_incident("INC-2", "APP-01")
        self.assertIsNotNone(room["attack_started_at"])
        # Sanity: it parses as a real, recent ISO timestamp (the _now_iso() fallback).
        parsed = datetime.fromisoformat(room["attack_started_at"])
        self.assertLess((datetime.now(timezone.utc) - parsed).total_seconds(), 60)

    def test_existing_room_for_incident_is_returned_unchanged(self):
        existing = {"room_id": "room-existing", "incident_id": "INC-3", "attack_started_at": "already-set"}
        room_manager.find_room_for_incident = lambda incident_id: existing

        room = room_manager.ensure_room_for_incident("INC-3", "APP-01", attack_started_at="2026-06-01T00:00:00+00:00")

        self.assertIs(room, existing)
        self.assertEqual(room["attack_started_at"], "already-set")  # not overwritten
        self.assertEqual(self.saved_rooms, [])  # nothing new was persisted


class RoomsRouterUsesScoredReportTests(unittest.TestCase):
    """Source-level regression guard: the room-detail endpoint must go through
    the same scored (`run_bridge`) report helper `incidents_router.py` uses,
    not the bare unscored `generate_report()` - otherwise a room's detail view
    would silently disagree with `/api/incidents/{id}/report` on the numbers,
    including the deferred/blue_started_at-anchored scoring clock."""

    def test_rooms_router_source_uses_scored_report_helper(self):
        path = os.path.join(_PKG_ROOT, "api", "rooms_router.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("from core.report_helpers import scored_report", source)
        self.assertIn("scored_report(incident_id, incident)", source)
        self.assertNotIn("from attense_core.evaluation.reports import generate_report", source)


if __name__ == "__main__":
    unittest.main()
