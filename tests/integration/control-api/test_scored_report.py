"""Regression test: the scoring pipeline is wired into the incident report.

Guards the gap where `report.py::generate_report()` returns only
{ttd, ttc, outcome} and the scoring engine (penalty rules, TTC decay,
difficulty bonus, verdict band) was never reached on a live incident. The
`GET /api/incidents/{id}/report` endpoint now returns `run_bridge()`'s merged
+ scored report; this exercises that same `run_bridge()` over live-style
fixture files (a Wazuh alert + analyst-action JSONL), with no Docker/auth.

    # from repo root
    py -m unittest discover -s tests/integration/control-api -p test_scored_report.py
"""

import json
import os
import sys
import tempfile
import uuid
import unittest
from datetime import datetime, timedelta, timezone

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from pipeline import bridge  # noqa: E402
from pipeline.bridge import run_bridge  # noqa: E402

INCIDENT = "scored-report-test"


def _write_alert(path: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    rec = {
        "event_id": "fix-alert", "incident_id": INCIDENT, "scenario_id": "APP-01",
        "actor_id": "wazuh", "target_id": "sandbox-target", "event_type": "alert_raised",
        "actor_type": "system", "target_type": "alert", "timestamp": ts,
        "outcome": "detected",
        "metadata": {"wazuh_rule_id": "31106", "source_ip": "172.21.0.1", "severity": "high"},
    }
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _write_analyst_actions(actions_dir: str) -> None:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(actions_dir, f"analyst-fixture_{date_str}.jsonl")
    t = 0
    with open(path, "w", encoding="utf-8") as fh:
        for et in ("investigation_started", "incident_confirmed", "evidence_preserved",
                   "containment_initiated", "containment_succeeded",
                   "eradication_completed", "recovery_validated"):
            t += 60
            fh.write(json.dumps({
                "analyst_id": "analyst-fixture", "incident_id": INCIDENT,
                "scenario_id": "APP-01", "event_type": et, "t_offset_sec": t,
                "detail": f"fixture {et}", "timestamp": 1.0 * t, "stored_at": 1.0 * t,
            }) + "\n")


class ScoredReportWiringTests(unittest.TestCase):
    def setUp(self):
        base_tmp = os.environ.get("ATTENSE_TEST_TMPDIR")
        if base_tmp:
            self.tmp = os.path.join(base_tmp, f"scored-report-{uuid.uuid4().hex}")
            os.makedirs(self.tmp, exist_ok=True)
        else:
            self.tmp = tempfile.mkdtemp()
        self.actions = os.path.join(self.tmp, "actions")
        os.makedirs(self.actions)
        # bridge reads these as module-level globals at call time — point them
        # at the fixture dir instead of the container's /attense paths.
        self._orig_mapped = bridge.MAPPED_EVENTS
        self._orig_actions = bridge.ACTIONS_DIR
        self._orig_store = bridge.EVENT_STORE_DIR
        bridge.MAPPED_EVENTS = os.path.join(self.tmp, "mapped_events.jsonl")
        bridge.ACTIONS_DIR = self.actions
        bridge.EVENT_STORE_DIR = None  # off by default; the merge test opts in

    def tearDown(self):
        bridge.MAPPED_EVENTS = self._orig_mapped
        bridge.ACTIONS_DIR = self._orig_actions
        bridge.EVENT_STORE_DIR = self._orig_store
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_bridge_produces_a_real_score(self):
        _write_alert(bridge.MAPPED_EVENTS)
        _write_analyst_actions(self.actions)

        report, events = run_bridge(INCIDENT)

        # the scoring engine ran: these keys are absent from the basic report
        self.assertIn("final_score", report)
        self.assertIn("verdict", report)
        self.assertIn("scoring_rules", report)
        self.assertEqual(len(report["scoring_rules"]), 9)
        self.assertIn(report["verdict"], {"excellent", "acceptable", "needs_review", "failed"})
        self.assertGreaterEqual(report["final_score"], 0.0)
        self.assertLessEqual(report["final_score"], 100.0)
        # and the basic report fields are still present (merged, not replaced)
        self.assertEqual(report["incident_id"], INCIDENT)
        self.assertIn("outcome", report)
        # both sources were merged (1 Wazuh alert + 7 analyst actions)
        self.assertEqual(len(events), 8)


    def test_deferred_room_scores_from_blue_start_and_keeps_contributions(self):
        t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        with open(bridge.MAPPED_EVENTS, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "event_id": "deferred-alert", "incident_id": INCIDENT,
                "scenario_id": "APP-01", "actor_id": "wazuh",
                "target_id": "sandbox-target", "event_type": "alert_raised",
                "actor_type": "system", "target_type": "alert",
                "timestamp": t0.isoformat(), "outcome": "detected",
                "metadata": {"severity": "high"},
            }) + "\n")

        action_path = os.path.join(self.actions, "analyst-deferred.jsonl")
        with open(action_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "analyst_id": "analyst-a", "incident_id": INCIDENT,
                "scenario_id": "APP-01", "event_type": "investigation_started",
                "detail": "opened case", "stored_at": (t0 + timedelta(minutes=5)).isoformat(),
            }) + "\n")

        original_room_context = bridge._room_context
        blue_start = t0 + timedelta(minutes=4)
        try:
            bridge._room_context = lambda _incident_id: {
                "room_id": "room-deferred",
                "exercise_mode": "deferred",
                "blue_started_at": blue_start.isoformat(),
                "blue_started_by": "analyst-a",
                "packaged_at": t0.isoformat(),
            }
            report, _events = run_bridge(INCIDENT)
        finally:
            bridge._room_context = original_room_context

        self.assertEqual(report["scoring_started_at"], blue_start.replace(tzinfo=None).isoformat())
        r01 = next(rule for rule in report["scoring_rules"] if rule["rule_id"].endswith("R01"))
        self.assertIn("t=60s", " ".join(r01["evidence"]))
        self.assertEqual(report["analyst_contributions"][0]["analyst_id"], "analyst-a")
        self.assertEqual(report["analyst_contributions"][0]["first_action_offset_sec"], 60.0)

    def test_no_events_raises_valueerror_for_the_endpoint_fallback(self):
        # the endpoint catches this exact ValueError and degrades to the basic
        # generate_report() — see incidents_router._scored_report.
        with self.assertRaises(ValueError):
            run_bridge("incident-with-no-durable-events")

    def test_build_and_write_report_persists_markdown_and_summary(self):
        # The exercise-end hook (room_manager._generate_final_reports) and the
        # CLI both go through this. It must score, write the markdown file, and
        # return a summary — without any VERTEX env (plain-text fallback).
        from pipeline.run_pipeline import build_and_write_report

        _write_alert(bridge.MAPPED_EVENTS)
        _write_analyst_actions(self.actions)

        result = build_and_write_report(INCIDENT, actions_dir=self.actions)
        self.assertIsNotNone(result)
        self.assertIn(result["verdict"], {"excellent", "acceptable", "needs_review", "failed"})
        self.assertIsNotNone(result["final_score"])
        # the markdown report file was actually written and is non-trivial
        self.assertTrue(os.path.isfile(result["report_path"]))
        with open(result["report_path"], encoding="utf-8") as fh:
            markdown = fh.read()
        self.assertIn("Incident Report", markdown)

    def test_build_and_write_report_none_when_no_events(self):
        # The hook skips (doesn't store / doesn't crash) when an incident has
        # nothing to score.
        from pipeline.run_pipeline import build_and_write_report

        self.assertIsNone(
            build_and_write_report("no-such-incident", actions_dir=self.actions)
        )

    def test_durable_redteam_events_anchor_start_time(self):
        # The core data-flow fix: red-team malicious_action_executed events live
        # ONLY in the durable store (they never reach mapped_events.jsonl, which
        # the signal-mapper fills with alert_raised only). run_bridge must merge
        # the store so start_time anchors on the ATTACK, not the alert — making
        # TTD a real interval instead of the degenerate ~0 it was before.
        from attense_core.models.standard_event import StandardEvent
        from attense_core.repositories.events import EventRepository

        store_dir = os.path.join(self.tmp, "event_store")
        bridge.EVENT_STORE_DIR = store_dir

        t0 = datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc)  # attack start
        EventRepository(store_dir).append(StandardEvent(
            event_id="rt-1", incident_id=INCIDENT, scenario_id="APP-01",
            actor_id="redteam-operator", target_id="http://target-agent",
            event_type="malicious_action_executed", actor_type="red_team",
            target_type="service", occurred_at=t0, outcome="success",
        ))
        # Wazuh alert 120s later — the only thing in mapped_events.jsonl.
        alert_ts = (t0 + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S")
        with open(bridge.MAPPED_EVENTS, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "event_id": "wz-1", "incident_id": INCIDENT, "scenario_id": "APP-01",
                "actor_id": "wazuh", "target_id": "sandbox-target",
                "event_type": "alert_raised", "actor_type": "system",
                "target_type": "alert", "timestamp": alert_ts, "outcome": "detected",
                "metadata": {"severity": "high"},
            }) + "\n")

        report, events = run_bridge(INCIDENT)

        ids = {e.event_id for e in events}
        self.assertIn("rt-1", ids)   # the red-team attack event was merged in
        self.assertIn("wz-1", ids)
        # start_time = attack (t0); detection = alert (t0+120s) => real TTD.
        self.assertEqual(report["ttd"], timedelta(seconds=120))

    def test_durable_store_dedups_overlapping_event_ids(self):
        # The store also contains the Wazuh alert_raised (it passes through
        # process_event), so the same event_id appears in both sources. The
        # merge must dedup, not double-count.
        from attense_core.models.standard_event import StandardEvent
        from attense_core.repositories.events import EventRepository

        store_dir = os.path.join(self.tmp, "event_store")
        bridge.EVENT_STORE_DIR = store_dir

        t0 = datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc)
        EventRepository(store_dir).append(StandardEvent(
            event_id="wz-1", incident_id=INCIDENT, scenario_id="APP-01",
            actor_id="wazuh", target_id="sandbox-target",
            event_type="alert_raised", actor_type="system",
            target_type="alert", occurred_at=t0, outcome="detected",
            metadata={"severity": "high"},
        ))
        with open(bridge.MAPPED_EVENTS, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "event_id": "wz-1", "incident_id": INCIDENT, "scenario_id": "APP-01",
                "actor_id": "wazuh", "target_id": "sandbox-target",
                "event_type": "alert_raised", "actor_type": "system",
                "target_type": "alert",
                "timestamp": t0.strftime("%Y-%m-%dT%H:%M:%S"), "outcome": "detected",
                "metadata": {"severity": "high"},
            }) + "\n")

        _report, events = run_bridge(INCIDENT)
        self.assertEqual([e.event_id for e in events], ["wz-1"])  # not duplicated


if __name__ == "__main__":
    unittest.main()
