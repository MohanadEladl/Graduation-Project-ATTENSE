"""Regression tests for the lab-mode channel-gating bug: a real exploit run
through the browser iframe (or anything not tagged via="attackbox") used to
flip `success` but leave the progress bar / task ladder frozen, because
`events_for_progress` was via-gated in lab mode while `success` was not.

    # from repo root
    py -m unittest discover -s tests/integration/red-team-api -p test_lab_progress.py
"""

import os
import sys
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

_HERE = os.path.dirname(os.path.abspath(__file__)) # tests/integration/red-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_RED_TEAM_DIR = os.path.join(_REPO, "apps", "red-team-api")
if _RED_TEAM_DIR not in sys.path:
    sys.path.insert(0, _RED_TEAM_DIR)

from backend import lab_progress, chain_engine


def _browser_events():
    """Events an operator would see after fully completing the brute_force
    module's lab-mode task ladder, but entirely through the browser iframe
    (via="browser") instead of the AttackBox terminal."""
    base_ts = 1000.0
    events = []
    for i in range(6):
        events.append({
            "event_type": "login_failed",
            "module_id": "brute_force",
            "via": "browser",
            "ts": base_ts + i,
            "severity": "info",
        })
    events.append({
        "event_type": "brute_force_pattern",
        "module_id": "brute_force",
        "via": "browser",
        "ts": base_ts + 10,
        "severity": "high",
    })
    events.append({
        "event_type": "login_success",
        "module_id": "brute_force",
        "via": "browser",
        "ts": base_ts + 11,
        "severity": "info",
    })
    events.append({
        "event_type": "credential_found",
        "module_id": "brute_force",
        "via": "browser",
        "ts": base_ts + 12,
        "severity": "high",
    })
    return events


class LabModeChannelGatingTests(unittest.TestCase):
    """compute() in mode="lab" must count non-attackbox evidence toward both
    the task ladder (progress_percent/completed_tasks) and `success` -- not
    just success alone."""

    def setUp(self):
        self._orig_fetch = lab_progress.fetch_events
        lab_progress.fetch_events = lambda **kwargs: _browser_events()

    def tearDown(self):
        lab_progress.fetch_events = self._orig_fetch

    def test_browser_evidence_completes_task_ladder_in_lab_mode(self):
        result = lab_progress.compute(
            module_id="brute_force",
            mission_started_at=0.0,
            mode="lab",
        )
        self.assertTrue(result["success"], "success should be true from browser-channel evidence")
        self.assertEqual(result["progress_percent"], 100,
                          "task ladder must also complete from browser-channel evidence, "
                          "not just the success flag")
        self.assertEqual(len(result["completed_tasks"]), len(result["tasks"]))

    def test_tutorial_mode_unaffected(self):
        """Sanity check: tutorial mode already counted any channel before this
        fix and must continue to do so."""
        result = lab_progress.compute(
            module_id="brute_force",
            mission_started_at=0.0,
            mode="tutorial",
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["progress_percent"], 100)


class ChainRequiresSuccessTests(unittest.TestCase):
    """A chain phase must not advance on progress_percent alone -- it must
    also require the module's success criteria to be genuinely met."""

    def setUp(self):
        self._orig_fetch = lab_progress.fetch_events
        chain_engine._CHAIN_SESSIONS.clear()

    def tearDown(self):
        lab_progress.fetch_events = self._orig_fetch
        chain_engine._CHAIN_SESSIONS.clear()

    def test_high_progress_without_success_does_not_advance(self):
        # recon's default (tutorial) task ladder has 4 tasks; success_tutorial
        # requires {"portal_visited", "recon_sequence_observed"}. Completing
        # tasks 1-3 (portal_visited + 3 areas + the hidden clue) reaches 75%
        # -- above the 60% chain threshold -- without ever triggering
        # recon_sequence_observed, so success stays False.
        def fake_fetch(**kwargs):
            return [
                {"event_type": "portal_visited", "module_id": "recon", "via": "browser", "ts": 1.0},
                {"event_type": "route_discovered", "module_id": "recon", "via": "browser", "ts": 2.0},
                {"event_type": "search_used", "module_id": "recon", "via": "browser", "ts": 3.0},
                {"event_type": "diagnostics_used", "module_id": "recon", "via": "browser", "ts": 4.0},
                {"event_type": "hidden_clue_accessed", "module_id": "recon", "via": "browser", "ts": 5.0},
            ]
        lab_progress.fetch_events = fake_fetch

        session = chain_engine.start_chain("full_compromise", session_id="sess-1")
        chain_session_id = session["id"]

        self.assertFalse(
            chain_engine.check_step_complete(chain_session_id),
            "recon's high task-ladder score without success_required evidence "
            "must not count as step-complete",
        )
        with self.assertRaises(ValueError):
            chain_engine.advance_chain(chain_session_id)

    def test_success_required_evidence_allows_advance(self):
        def fake_fetch(**kwargs):
            return [
                {"event_type": "portal_visited", "module_id": "recon", "via": "browser", "ts": 1.0},
                {"event_type": "route_discovered", "module_id": "recon", "via": "browser", "ts": 2.0},
                {"event_type": "search_used", "module_id": "recon", "via": "browser", "ts": 3.0},
                {"event_type": "diagnostics_used", "module_id": "recon", "via": "browser", "ts": 4.0},
                {"event_type": "hidden_clue_accessed", "module_id": "recon", "via": "browser", "ts": 5.0},
                {"event_type": "recon_sequence_observed", "module_id": "recon", "via": "browser", "ts": 6.0},
            ]
        lab_progress.fetch_events = fake_fetch

        session = chain_engine.start_chain("full_compromise", session_id="sess-2")
        chain_session_id = session["id"]
        self.assertTrue(chain_engine.check_step_complete(chain_session_id))

        # Reset call in advance_chain() hits target-agent over HTTP; fail it
        # fast instead of waiting out a real DNS timeout (it's caught either
        # way -- see chain_engine.advance_chain's try/except around the reset).
        with patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("no target-agent in tests")):
            advanced = chain_engine.advance_chain(chain_session_id)
        self.assertEqual(advanced["current_step_index"], 1)
        self.assertTrue(advanced["phase_results"][0]["success"])


if __name__ == "__main__":
    unittest.main()
