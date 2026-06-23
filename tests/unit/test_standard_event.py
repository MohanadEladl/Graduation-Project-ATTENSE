"""Tests for the canonical event contract (Phase 2).

Covers StandardEvent validation (enums, UTC-aware-only `occurred_at`, the legacy
`timestamp` alias, strict extra-field rejection), the producer adapters, the
bridge down to the legacy `Event` / incident state machine, and that the enums
stay in sync with the legacy `allowed_events` sets and the committed JSON schema.

Requires pydantic (every ATTENSE service pins it). Runs on the host or in CI:

    # from repo root
    py -m unittest tests.unit.test_standard_event
"""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from ATTENSE_app.events.allowed_events import (
    ALLOWED_ACTOR_TYPES,
    ALLOWED_EVENT_TYPES,
    ALLOWED_OUTCOMES,
    ALLOWED_TARGET_TYPES,
)
from ATTENSE_app.events.constants import (
    ActorType,
    EventSource,
    EventType,
    IncidentStatus,
    Outcome,
    TargetType,
)
from ATTENSE_app.events.standard_event import SCHEMA_VERSION, StandardEvent
from ATTENSE_app.incidents.incident import Incident

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

CANONICAL = {
    "event_id": "E1",
    "incident_id": "INC-1",
    "scenario_id": "APP-01",
    "source": "red-team",
    "actor_id": "operator-1",
    "actor_type": "red_team",
    "target_id": "http://target",
    "target_type": "service",
    "event_type": "malicious_action_executed",
    "occurred_at": "2026-01-01T10:00:00+00:00",
    "outcome": "success",
    "metadata": {"module_id": "xss-01"},
}


def _legacy_payload(**overrides):
    """A red-team-style payload using the legacy `timestamp` field, no source."""
    payload = {
        "event_id": "E1",
        "incident_id": "INC-1",
        "scenario_id": "APP-01",
        "actor_id": "operator-1",
        "actor_type": "red_team",
        "target_id": "http://target",
        "target_type": "service",
        "event_type": "malicious_action_executed",
        "timestamp": "2026-01-01T10:00:00+00:00",
        "outcome": "success",
        "metadata": {},
    }
    payload.update(overrides)
    return payload


class StandardEventValidationTests(unittest.TestCase):
    def test_canonical_payload_validates(self):
        ev = StandardEvent.model_validate(CANONICAL)
        self.assertEqual(ev.event_type, EventType.MALICIOUS_ACTION_EXECUTED)
        self.assertEqual(ev.actor_type, ActorType.RED_TEAM)
        self.assertEqual(ev.target_type, TargetType.SERVICE)
        self.assertEqual(ev.source, EventSource.RED_TEAM)
        self.assertEqual(ev.outcome, Outcome.SUCCESS)
        self.assertEqual(ev.occurred_at, T0)

    def test_defaults(self):
        ev = StandardEvent.model_validate(_legacy_payload(metadata=None))
        self.assertEqual(ev.schema_version, SCHEMA_VERSION)
        self.assertEqual(ev.source, EventSource.UNKNOWN)
        self.assertIsNone(ev.room_id)
        self.assertIsNone(ev.run_id)
        self.assertEqual(ev.metadata, {})

    def test_legacy_timestamp_aliases_occurred_at(self):
        ev = StandardEvent.model_validate(_legacy_payload())
        self.assertEqual(ev.occurred_at, T0)

    def test_missing_time_defaults_to_now_utc(self):
        payload = _legacy_payload()
        payload.pop("timestamp")
        ev = StandardEvent.model_validate(payload)
        self.assertIsNotNone(ev.occurred_at.tzinfo)

    def test_aware_non_utc_is_normalized_to_utc(self):
        payload = _legacy_payload(timestamp="2026-01-01T12:00:00+02:00")
        ev = StandardEvent.model_validate(payload)
        self.assertEqual(ev.occurred_at, T0)  # 12:00+02:00 == 10:00Z
        self.assertEqual(ev.occurred_at.utcoffset(), timedelta(0))

    def test_naive_timestamp_string_is_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(timestamp="2026-01-01T10:00:00"))

    def test_naive_datetime_is_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(timestamp=datetime(2026, 1, 1, 10)))

    def test_bad_iso_string_is_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(timestamp="not-a-time"))

    def test_invalid_event_type_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(event_type="hack_the_planet"))

    def test_invalid_actor_type_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(actor_type="purple_team"))

    def test_invalid_target_type_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(target_type="database"))

    def test_invalid_outcome_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(outcome="maybe"))

    def test_extra_field_rejected(self):
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(_legacy_payload(rogue_field="x"))

    def test_missing_required_field_rejected(self):
        payload = _legacy_payload()
        payload.pop("event_id")
        with self.assertRaises(ValidationError):
            StandardEvent.model_validate(payload)


class LegacyBridgeTests(unittest.TestCase):
    def test_to_legacy_event_uses_string_enum_values(self):
        ev = StandardEvent.model_validate(CANONICAL)
        legacy = ev.to_legacy_event()
        self.assertEqual(legacy.event_type, "malicious_action_executed")
        self.assertEqual(legacy.actor_type, "red_team")
        self.assertEqual(legacy.target_type, "service")
        self.assertEqual(legacy.outcome, "success")
        self.assertEqual(legacy.timestamp, T0)

    def test_to_legacy_event_folds_contract_fields_into_metadata(self):
        ev = StandardEvent.model_validate(
            {**CANONICAL, "room_id": "room-7", "run_id": "run-3"}
        )
        legacy = ev.to_legacy_event()
        self.assertEqual(legacy.metadata["source"], "red-team")
        self.assertEqual(legacy.metadata["schema_version"], SCHEMA_VERSION)
        self.assertEqual(legacy.metadata["room_id"], "room-7")
        self.assertEqual(legacy.metadata["run_id"], "run-3")
        self.assertEqual(legacy.metadata["module_id"], "xss-01")  # original kept

    def test_to_legacy_event_dict_uses_timestamp_key(self):
        ev = StandardEvent.model_validate(CANONICAL)
        d = ev.to_legacy_event_dict()
        self.assertIn("timestamp", d)
        self.assertNotIn("occurred_at", d)
        self.assertEqual(d["timestamp"], T0.isoformat())

    def test_bridged_event_drives_incident_state_machine(self):
        ev = StandardEvent.model_validate(CANONICAL)
        inc = Incident("INC-1", "APP-01")
        inc.apply_event(ev.to_legacy_event())
        self.assertEqual(inc.status, "ACTIVE_UNDETECTED")
        self.assertEqual(inc.start_time, T0)


class AdapterTests(unittest.TestCase):
    def test_from_redteam_payload_defaults_source(self):
        ev = StandardEvent.from_redteam_payload(_legacy_payload())
        self.assertEqual(ev.source, EventSource.RED_TEAM)

    def test_from_redteam_payload_keeps_explicit_source(self):
        ev = StandardEvent.from_redteam_payload(_legacy_payload(source="test"))
        self.assertEqual(ev.source, EventSource.TEST)

    def test_from_wazuh_event_lifts_legacy_event(self):
        from ATTENSE_app.events.event import Event

        wazuh = Event(
            event_id="w1",
            incident_id="wazuh-123",
            scenario_id="APP-01",
            actor_id="wazuh",
            target_id="agent-1",
            event_type="alert_raised",
            actor_type="system",
            target_type="service",
            timestamp="2026-01-01T10:00:00+00:00",
            outcome="detected",
            metadata={"wazuh_rule_id": "100200"},
        )
        ev = StandardEvent.from_wazuh_event(wazuh, room_id="room-1")
        self.assertEqual(ev.source, EventSource.SIGNAL_STORE)
        self.assertEqual(ev.event_type, EventType.ALERT_RAISED)
        self.assertEqual(ev.outcome, Outcome.DETECTED)
        self.assertEqual(ev.room_id, "room-1")
        self.assertEqual(ev.metadata["wazuh_rule_id"], "100200")

    def test_from_blueteam_event_sets_source(self):
        ev = StandardEvent.from_blueteam_event(_legacy_payload(event_type="containment_succeeded", actor_type="blue_team", target_type="host"))
        self.assertEqual(ev.source, EventSource.BLUE_TEAM)


class EnumSyncTests(unittest.TestCase):
    """The typed enums must stay in lockstep with the legacy validator sets and
    the incident state-machine status strings (pinned by the Phase 1 tests)."""

    def test_event_types_match_allowed(self):
        self.assertEqual({e.value for e in EventType}, ALLOWED_EVENT_TYPES)

    def test_actor_types_match_allowed(self):
        self.assertEqual({a.value for a in ActorType}, ALLOWED_ACTOR_TYPES)

    def test_target_types_match_allowed(self):
        self.assertEqual({t.value for t in TargetType}, ALLOWED_TARGET_TYPES)

    def test_outcomes_match_allowed(self):
        self.assertEqual({o.value for o in Outcome}, ALLOWED_OUTCOMES)

    def test_incident_status_values_match_state_machine(self):
        # Exactly the statuses Incident.apply_event can produce (+ initial).
        expected = {
            "NOT_STARTED",
            "ACTIVE_UNDETECTED",
            "INVESTIGATING",
            "DETECTED",
            "CONTAINING",
            "CONTAINMENT_FAILED",
            "CONTAINED",
            "FALSE_POSITIVE",
            "ENDED",
        }
        self.assertEqual({s.value for s in IncidentStatus}, expected)


class GeneratedSchemaTests(unittest.TestCase):
    """The committed JSON schema is generated from the model; assert it is
    structurally consistent with the model (robust across pydantic minor
    versions). Run scripts/generate_event_schema.py --check for byte-exactness."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(
            _CORE_ROOT, "attense_core", "models", "standard_event.schema.json",
        )
        with open(path, encoding="utf-8") as fh:
            cls.schema = json.load(fh)
        cls.model_schema = StandardEvent.model_json_schema()

    def test_schema_file_matches_model_structure(self):
        self.assertEqual(self.schema["title"], "StandardEvent")
        self.assertEqual(
            set(self.schema["properties"]),
            set(self.model_schema["properties"]),
        )
        self.assertEqual(
            set(self.schema["required"]),
            set(self.model_schema["required"]),
        )

    def test_schema_required_excludes_fields_with_defaults(self):
        required = set(self.schema["required"])
        # These all have defaults / aliases, so must not be required.
        for optional in ("schema_version", "source", "room_id", "run_id", "outcome", "metadata"):
            self.assertNotIn(optional, required)
        # occurred_at has no field default (the alias/validator supplies it), so
        # it is required in the schema even though `timestamp` is accepted.
        self.assertIn("occurred_at", required)


if __name__ == "__main__":
    unittest.main()
