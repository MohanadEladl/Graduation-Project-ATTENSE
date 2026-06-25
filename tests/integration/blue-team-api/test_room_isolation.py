"""Phase 5 cross-room isolation tests for the Blue Team.

Exit condition: two rooms sharing one Blue Team instance cannot read or modify
each other's incidents. Enforcement lives in the data layer (EventEmitter), with
authorization (require_room) at the API edge.

    # from repo root (discover, not dotted import -- "blue-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/blue-team-api -p test_room_isolation.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/blue-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_BLUE_TEAM_SERVICE_DIR = os.path.join(_REPO, "apps", "blue-team-api")
for path in (_BLUE_TEAM_SERVICE_DIR, os.path.join(_REPO, "apps", "control-api"), os.path.join(_REPO, "packages", "attense-core")):
    if path not in sys.path:
        sys.path.insert(0, path)

from fastapi import HTTPException

from blueteam.api.dependencies import require_room
from blueteam.core.services.alert_service import investigate_alert
from blueteam.infrastructure.eventstore.event_emitter import (
    CrossRoomAccessError,
    EventEmitter,
)
from blueteam.schemas.requests.alert_requests import InvestigateAlertRequest


class EmitterIsolationTests(unittest.TestCase):
    def setUp(self):
        self.emitter = EventEmitter()

    def test_same_room_reuses_incident(self):
        inc1, _ = self.emitter.get_or_create("room-A", "INC", "APP-01")
        inc2, _ = self.emitter.get_or_create("room-A", "INC", "APP-01")
        self.assertIs(inc1, inc2)
        self.assertEqual(self.emitter.room_of("INC"), "room-A")

    def test_cross_room_get_or_create_is_denied(self):
        self.emitter.get_or_create("room-A", "INC", "APP-01")
        with self.assertRaises(CrossRoomAccessError):
            self.emitter.get_or_create("room-B", "INC", "APP-01")

    def test_cross_room_get_incident_is_denied(self):
        self.emitter.get_or_create("room-A", "INC", "APP-01")
        with self.assertRaises(CrossRoomAccessError):
            self.emitter.get_incident("room-B", "INC")

    def test_same_room_get_incident_ok(self):
        self.emitter.get_or_create("room-A", "INC", "APP-01")
        self.assertIsNotNone(self.emitter.get_incident("room-A", "INC"))

    def test_all_incidents_is_room_scoped(self):
        self.emitter.get_or_create("room-A", "INC-A", "APP-01")
        self.emitter.get_or_create("room-B", "INC-B", "APP-02")
        self.assertEqual(set(self.emitter.all_incidents("room-A")), {"INC-A"})
        self.assertEqual(set(self.emitter.all_incidents("room-B")), {"INC-B"})
        self.assertEqual(set(self.emitter.all_incidents()), {"INC-A", "INC-B"})

    def test_same_incident_id_in_two_rooms_is_blocked(self):
        # Even if two rooms collide on an incident_id, the second is denied —
        # the first room owns it.
        self.emitter.get_or_create("room-A", "SHARED", "APP-01")
        with self.assertRaises(CrossRoomAccessError):
            self.emitter.get_or_create("room-B", "SHARED", "APP-01")


class RequireRoomTests(unittest.TestCase):
    def test_returns_room_from_header(self):
        self.assertEqual(require_room("room-A"), "room-A")

    def test_missing_room_is_401(self):
        with self.assertRaises(HTTPException) as ctx:
            require_room(None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_empty_room_is_401(self):
        with self.assertRaises(HTTPException) as ctx:
            require_room("")
        self.assertEqual(ctx.exception.status_code, 401)


class ServiceLayerIsolationTests(unittest.TestCase):
    def test_analyst_action_in_wrong_room_is_denied(self):
        emitter = EventEmitter()
        # Room A opens the incident.
        emitter.get_or_create("room-A", "INC", "APP-01")
        # Room B tries to drive an analyst action on it through the service.
        body = InvestigateAlertRequest(
            incident_id="INC", scenario_id="APP-01",
            analyst_id="analyst-B", alert_id="alert-1",
        )
        with self.assertRaises(CrossRoomAccessError):
            investigate_alert(body=body, emitter=emitter, room_id="room-B")

    def test_analyst_action_in_owning_room_is_allowed_past_isolation(self):
        # Same room passes the isolation gate (it may still fail later business
        # validation, which is a different 409 concern, not a 403 isolation one).
        emitter = EventEmitter()
        emitter.get_or_create("room-A", "INC", "APP-01")
        body = InvestigateAlertRequest(
            incident_id="INC", scenario_id="APP-01",
            analyst_id="analyst-A", alert_id="alert-1",
        )
        try:
            investigate_alert(body=body, emitter=emitter, room_id="room-A")
        except CrossRoomAccessError:
            self.fail("owning room must not hit a cross-room error")
        except Exception:
            pass  # business-rule ValueError is fine here; isolation is what we test


if __name__ == "__main__":
    unittest.main()
