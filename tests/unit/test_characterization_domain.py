"""Characterization tests for the ATTENSE incident-evaluation domain layer.

Phase 1 of ATTENSE_Refactoring_Optimization_Report.md: lock down the CURRENT
behaviour of the event / incident / metrics / outcome / report layer *before*
the Phase 2/3 rewrite (StandardEvent + SQLite EventRepository + IncidentProjection
+ explicit state-machine table) so any change in behaviour is caught.

These are characterization tests: they assert what the code does *today*, quirks
and all. Where the pinned behaviour is a known bug the report wants fixed, the
test name and a comment say so. When Phase 2/3 intentionally changes one of
these contracts, the corresponding test is expected to fail and must be updated
deliberately (that failure is the signal, not a regression to silence).

Pure-stdlib domain layer, so this runs with no third-party deps:

    # from repo root
    py -m unittest tests.unit.test_characterization_domain

(pytest also collects these unittest.TestCase classes for the Phase 9 CI suite.)
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

# Make the control-api package root importable however this file is invoked
# (direct run, `-m unittest`, or pytest), without relying on PYTHONPATH.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from ATTENSE_app.events.event import Event
from ATTENSE_app.events.event_store import EventStore
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.matrics.metrics import TTC_calculation, TTD_calculation
from ATTENSE_app.Outcomes.outcome import classify_outcome, is_false_positive
from ATTENSE_app.reports.report import generate_report

# Fixed UTC anchor for deterministic TTD/TTC arithmetic (report Phase 1, item 2).
T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type,
    *,
    incident_id="INC-1",
    ts=None,
    scenario_id="SCN-1",
    actor_id="actor-1",
    target_id="target-1",
    actor_type="system",
    target_type="service",
    outcome=None,
    metadata=None,
    event_id="E",
):
    """Build an Event with sensible valid defaults; override per test."""
    return Event(
        event_id=event_id,
        incident_id=incident_id,
        scenario_id=scenario_id,
        actor_id=actor_id,
        target_id=target_id,
        event_type=event_type,
        actor_type=actor_type,
        target_type=target_type,
        timestamp=ts if ts is not None else T0,
        outcome=outcome,
        metadata=metadata,
    )


class EventModelTests(unittest.TestCase):
    def test_to_dict_roundtrip(self):
        e = make_event("malicious_action_executed", ts=T0, outcome="success", metadata={"k": 1})
        d = e.to_dict()
        self.assertEqual(d["timestamp"], T0.isoformat())
        self.assertEqual(d["outcome"], "success")
        self.assertEqual(d["metadata"], {"k": 1})
        self.assertEqual(d["event_type"], "malicious_action_executed")

    def test_timestamp_iso_string_is_parsed(self):
        e = make_event("alert_raised", ts="2026-01-01T10:00:00+00:00")
        self.assertEqual(e.timestamp, datetime.fromisoformat("2026-01-01T10:00:00+00:00"))

    def test_timestamp_none_defaults_to_now(self):
        e = make_event("alert_raised", ts=None)
        self.assertIsInstance(e.timestamp, datetime)

    def test_invalid_iso_string_raises_valueerror(self):
        with self.assertRaises(ValueError):
            make_event("alert_raised", ts="not-a-timestamp")

    def test_non_datetime_non_string_timestamp_raises_typeerror(self):
        with self.assertRaises(TypeError):
            make_event("alert_raised", ts=12345)

    def test_invalid_event_type_raises(self):
        with self.assertRaises(ValueError):
            make_event("not_a_real_event")

    def test_invalid_actor_type_raises(self):
        with self.assertRaises(ValueError):
            make_event("alert_raised", actor_type="purple_team")

    def test_invalid_target_type_raises(self):
        with self.assertRaises(ValueError):
            make_event("alert_raised", target_type="database")

    def test_invalid_outcome_raises(self):
        with self.assertRaises(ValueError):
            make_event("alert_raised", outcome="maybe")

    def test_none_outcome_is_allowed(self):
        e = make_event("alert_raised", outcome=None)
        self.assertIsNone(e.outcome)

    def test_naive_timestamp_is_currently_accepted(self):
        # CHARACTERIZATION / known gap: the report (Phase 2) wants naive
        # timestamps rejected and stored as UTC-with-offset. Today they pass
        # through untouched. This test should flip to assertRaises when that
        # contract lands.
        naive = datetime(2026, 1, 1, 10, 0, 0)
        e = make_event("alert_raised", ts=naive)
        self.assertIsNone(e.timestamp.tzinfo)


class IncidentStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.inc = Incident("INC-1", "SCN-1")

    def test_initial_state(self):
        self.assertEqual(self.inc.status, "NOT_STARTED")
        self.assertIsNone(self.inc.start_time)
        self.assertIsNone(self.inc.detection_time)
        self.assertIsNone(self.inc.containment_time)
        self.assertIsNone(self.inc.end_time)
        self.assertEqual(self.inc.events, [])

    def test_event_for_another_incident_is_ignored(self):
        self.inc.apply_event(make_event("malicious_action_executed", incident_id="OTHER", ts=T0))
        self.assertEqual(self.inc.events, [])
        self.assertEqual(self.inc.status, "NOT_STARTED")
        self.assertIsNone(self.inc.start_time)

    def test_malicious_action_starts_incident(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.assertEqual(self.inc.status, "ACTIVE_UNDETECTED")
        self.assertEqual(self.inc.start_time, T0)

    def test_second_malicious_action_does_not_move_start_time(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0 + timedelta(minutes=5)))
        self.assertEqual(self.inc.start_time, T0)
        self.assertEqual(len(self.inc.events), 2)

    def test_alert_raised_sets_detection_and_start_fallback_without_status_change(self):
        # From NOT_STARTED, alert_raised anchors detection AND back-fills
        # start_time, but does NOT advance status (it stays NOT_STARTED).
        self.inc.apply_event(make_event("alert_raised", ts=T0))
        self.assertEqual(self.inc.detection_time, T0)
        self.assertEqual(self.inc.start_time, T0)  # phase-2 fallback fired
        self.assertEqual(self.inc.status, "NOT_STARTED")

    def test_alert_raised_after_malicious_does_not_overwrite_start(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.inc.apply_event(make_event("alert_raised", ts=T0 + timedelta(minutes=3)))
        self.assertEqual(self.inc.start_time, T0)
        self.assertEqual(self.inc.detection_time, T0 + timedelta(minutes=3))
        self.assertEqual(self.inc.status, "ACTIVE_UNDETECTED")

    def test_investigation_started_moves_to_investigating(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.inc.apply_event(make_event("alert_investigation_started", ts=T0 + timedelta(minutes=2)))
        self.assertEqual(self.inc.status, "INVESTIGATING")
        self.assertEqual(self.inc.investigation_time, T0 + timedelta(minutes=2))

    def test_incident_confirmed_marks_detected(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.inc.apply_event(make_event("incident_confirmed", ts=T0 + timedelta(minutes=4)))
        self.assertEqual(self.inc.status, "DETECTED")
        self.assertEqual(self.inc.detection_time, T0 + timedelta(minutes=4))

    def test_incident_confirmed_from_investigating(self):
        self.inc.apply_event(make_event("alert_investigation_started", ts=T0))
        self.inc.apply_event(make_event("incident_confirmed", ts=T0 + timedelta(minutes=1)))
        self.assertEqual(self.inc.status, "DETECTED")

    def test_containment_initiated_moves_to_containing(self):
        self.inc.apply_event(make_event("incident_confirmed", ts=T0))
        self.inc.apply_event(make_event("containment_initiated", ts=T0 + timedelta(minutes=1)))
        self.assertEqual(self.inc.status, "CONTAINING")
        self.assertEqual(self.inc.containment_start_time, T0 + timedelta(minutes=1))

    def test_containment_failed_increments_counter_and_sets_status(self):
        self.inc.apply_event(make_event("containment_failed", ts=T0))
        self.assertEqual(self.inc.status, "CONTAINMENT_FAILED")
        self.assertEqual(self.inc.containment_failures, 1)
        self.inc.apply_event(make_event("containment_failed", ts=T0 + timedelta(minutes=1)))
        self.assertEqual(self.inc.containment_failures, 2)

    def test_containment_succeeded_moves_to_contained(self):
        self.inc.apply_event(make_event("incident_confirmed", ts=T0))
        self.inc.apply_event(make_event("containment_succeeded", ts=T0 + timedelta(minutes=5)))
        self.assertEqual(self.inc.status, "CONTAINED")
        self.assertEqual(self.inc.containment_time, T0 + timedelta(minutes=5))

    def test_alert_denied_marks_false_positive(self):
        self.inc.apply_event(make_event("alert_denied", ts=T0))
        self.assertEqual(self.inc.status, "FALSE_POSITIVE")
        self.assertEqual(self.inc.end_time, T0)

    def test_incident_ended_marks_ended(self):
        self.inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.inc.apply_event(make_event("incident_ended", ts=T0 + timedelta(minutes=10)))
        self.assertEqual(self.inc.status, "ENDED")
        self.assertEqual(self.inc.end_time, T0 + timedelta(minutes=10))

    def test_incident_ended_after_false_positive_keeps_false_positive(self):
        self.inc.apply_event(make_event("alert_denied", ts=T0))
        self.inc.apply_event(make_event("incident_ended", ts=T0 + timedelta(minutes=2)))
        self.assertEqual(self.inc.status, "FALSE_POSITIVE")
        # end_time is first-write-wins: stays the alert_denied timestamp.
        self.assertEqual(self.inc.end_time, T0)

    def test_containment_after_ended_keeps_ended_but_still_stamps_time(self):
        # CHARACTERIZATION quirk: status is guarded by `!= ENDED`, but the
        # containment_start_time field has no such guard and is still set.
        self.inc.apply_event(make_event("incident_ended", ts=T0))
        self.inc.apply_event(make_event("containment_initiated", ts=T0 + timedelta(minutes=1)))
        self.assertEqual(self.inc.status, "ENDED")
        self.assertEqual(self.inc.containment_start_time, T0 + timedelta(minutes=1))

    def test_timestamps_are_first_write_wins(self):
        self.inc.apply_event(make_event("incident_confirmed", ts=T0))
        self.inc.apply_event(make_event("incident_confirmed", ts=T0 + timedelta(minutes=9)))
        self.assertEqual(self.inc.detection_time, T0)


class DuplicateAndOutOfOrderTests(unittest.TestCase):
    """Report Phase 1, item 3 + the correlation bugs Phase 4 targets."""

    def test_duplicate_event_id_is_not_deduplicated(self):
        # CHARACTERIZATION / known gap: there is NO idempotency by event_id.
        # The report's Phase 2/3 adds a unique event_id constraint; until then
        # a replayed event is counted twice.
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("containment_failed", ts=T0, event_id="DUP"))
        inc.apply_event(make_event("containment_failed", ts=T0, event_id="DUP"))
        self.assertEqual(inc.containment_failures, 2)
        self.assertEqual(len(inc.events), 2)

    def test_out_of_order_containment_before_detection_yields_negative_ttc(self):
        # CHARACTERIZATION / known bug: events applied out of order produce a
        # negative TTC because metrics just subtract whatever anchors exist.
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("containment_succeeded", ts=T0 + timedelta(minutes=5)))
        inc.apply_event(make_event("incident_confirmed", ts=T0 + timedelta(minutes=10)))
        self.assertEqual(inc.containment_time, T0 + timedelta(minutes=5))
        self.assertEqual(inc.detection_time, T0 + timedelta(minutes=10))
        self.assertEqual(TTC_calculation(inc), timedelta(minutes=-5))

    def test_alert_before_malicious_yields_zero_ttd_and_stuck_status(self):
        # CHARACTERIZATION / known bug (report Phase 4): if the alert arrives
        # before the attack event, start_time is back-filled to the alert time,
        # so TTD collapses to zero. The later malicious_action also can't start
        # the incident (start_time is already set), so status stays NOT_STARTED.
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("alert_raised", ts=T0))
        inc.apply_event(make_event("malicious_action_executed", ts=T0 + timedelta(minutes=5)))
        self.assertEqual(inc.start_time, T0)
        self.assertEqual(inc.detection_time, T0)
        self.assertEqual(inc.status, "NOT_STARTED")
        self.assertEqual(TTD_calculation(inc), timedelta(0))


class MetricsTests(unittest.TestCase):
    """Report Phase 1, item 2 — TTD/TTC against fixed UTC timestamps."""

    def _incident_with(self, start=None, detection=None, containment=None):
        inc = Incident("INC-1", "SCN-1")
        inc.start_time = start
        inc.detection_time = detection
        inc.containment_time = containment
        return inc

    def test_ttd_normal(self):
        inc = self._incident_with(start=T0, detection=T0 + timedelta(minutes=4))
        self.assertEqual(TTD_calculation(inc), timedelta(minutes=4))

    def test_ttd_none_when_start_missing(self):
        inc = self._incident_with(detection=T0)
        self.assertIsNone(TTD_calculation(inc))

    def test_ttd_none_when_detection_missing(self):
        inc = self._incident_with(start=T0)
        self.assertIsNone(TTD_calculation(inc))

    def test_ttc_normal(self):
        inc = self._incident_with(detection=T0 + timedelta(minutes=4), containment=T0 + timedelta(minutes=9))
        self.assertEqual(TTC_calculation(inc), timedelta(minutes=5))

    def test_ttc_none_when_detection_missing(self):
        inc = self._incident_with(containment=T0)
        self.assertIsNone(TTC_calculation(inc))

    def test_ttc_none_when_containment_missing(self):
        inc = self._incident_with(detection=T0)
        self.assertIsNone(TTC_calculation(inc))


class OutcomeTests(unittest.TestCase):
    def _ended(self, detection=True, containment=True):
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("malicious_action_executed", ts=T0))
        if detection:
            inc.apply_event(make_event("incident_confirmed", ts=T0 + timedelta(minutes=2)))
        if containment:
            inc.apply_event(make_event("containment_succeeded", ts=T0 + timedelta(minutes=5)))
        inc.apply_event(make_event("incident_ended", ts=T0 + timedelta(minutes=10)))
        return inc

    def test_ended_detected_and_contained_is_success(self):
        self.assertEqual(classify_outcome(self._ended()), "SUCCESS")

    def test_ended_detected_not_contained_is_partial(self):
        self.assertEqual(classify_outcome(self._ended(containment=False)), "PARTIAL")

    def test_ended_not_detected_is_failure(self):
        self.assertEqual(classify_outcome(self._ended(detection=False, containment=False)), "FAILURE")

    def test_active_incident_is_incomplete(self):
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("malicious_action_executed", ts=T0))
        self.assertEqual(classify_outcome(inc), "INCOMPLETE")

    def test_lone_alert_raised_is_incomplete_not_false_positive(self):
        # CHARACTERIZATION / known bug: is_false_positive() requires
        # start_time is None, but alert_raised back-fills start_time, so the
        # false-positive path is unreachable and a lone alert reads INCOMPLETE.
        # (The stale ATTENSE_app/tests/Testing.py still asserts FALSE_POSITIVE
        # here and therefore fails against the current code.)
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("alert_raised", ts=T0))
        self.assertFalse(is_false_positive(inc))
        self.assertEqual(classify_outcome(inc), "INCOMPLETE")

    def test_alert_denied_status_is_fp_but_outcome_is_incomplete(self):
        # CHARACTERIZATION quirk: alert_denied sets status FALSE_POSITIVE, but
        # classify_outcome has no case for it and is_false_positive() is False
        # (no alert_raised), so the reported outcome is INCOMPLETE.
        inc = Incident("INC-1", "SCN-1")
        inc.apply_event(make_event("alert_denied", ts=T0))
        self.assertEqual(inc.status, "FALSE_POSITIVE")
        self.assertEqual(classify_outcome(inc), "INCOMPLETE")


class EventStoreTests(unittest.TestCase):
    def test_add_and_get_groups_by_incident(self):
        store = EventStore()
        store.add_event(make_event("malicious_action_executed", incident_id="A", event_id="1"))
        store.add_event(make_event("alert_raised", incident_id="A", event_id="2"))
        store.add_event(make_event("alert_raised", incident_id="B", event_id="3"))
        self.assertEqual(len(store.get_events("A")), 2)
        self.assertEqual(len(store.get_events("B")), 1)

    def test_get_unknown_incident_returns_empty(self):
        self.assertEqual(EventStore().get_events("nope"), [])

    def test_has_event(self):
        store = EventStore()
        store.add_event(make_event("alert_raised", incident_id="A"))
        self.assertTrue(store.has_event("A", "alert_raised"))
        self.assertFalse(store.has_event("A", "containment_succeeded"))
        self.assertFalse(store.has_event("unknown", "alert_raised"))


class IntegrationHappyPathTest(unittest.TestCase):
    """Report Phase 1, item 4 — the full realistic lifecycle, end to end,
    asserted at the report level with fixed UTC timestamps."""

    def test_full_lifecycle_report(self):
        inc = Incident("INC-1", "SCN-1")
        sequence = [
            ("malicious_action_executed", 0, "red_team", "service"),
            ("alert_raised", 2, "system", "alert"),
            ("alert_investigation_started", 3, "blue_team", "alert"),
            ("incident_confirmed", 4, "blue_team", "alert"),
            ("containment_initiated", 6, "blue_team", "host"),
            ("containment_succeeded", 9, "blue_team", "host"),
            ("incident_ended", 12, "system", "service"),
        ]
        for i, (etype, minutes, actor, target) in enumerate(sequence):
            inc.apply_event(
                make_event(
                    etype,
                    ts=T0 + timedelta(minutes=minutes),
                    actor_type=actor,
                    target_type=target,
                    event_id=f"E{i}",
                )
            )

        report = generate_report(inc)
        self.assertEqual(report["status"], "ENDED")
        self.assertEqual(report["start_time"], T0)
        self.assertEqual(report["detection_time"], T0 + timedelta(minutes=2))
        self.assertEqual(report["containment_time"], T0 + timedelta(minutes=9))
        self.assertEqual(report["end_time"], T0 + timedelta(minutes=12))
        self.assertEqual(report["ttd"], timedelta(minutes=2))
        self.assertEqual(report["ttc"], timedelta(minutes=7))
        self.assertEqual(report["outcome"], "SUCCESS")
        self.assertEqual(len(inc.events), len(sequence))


if __name__ == "__main__":
    unittest.main()
