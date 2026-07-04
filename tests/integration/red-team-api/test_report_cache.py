"""Regression tests for the report-cache invalidation bug.

GET /api/sessions/{sid}/report used to cache its result forever once
generated, with nothing but the explicit /report/regenerate endpoint able to
clear it -- not a reset/restart, and not a fresh mission success. These tests
exercise _do_reset_evidence() and check_progress() directly (bypassing the
FastAPI dependency-injection layer, which is fine since they're plain
async functions) to prove report_cache is invalidated in both cases.

    # from repo root (discover, not dotted import -- "red-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/red-team-api -p test_report_cache.py
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

from backend import main, lab_progress
from backend.session_manager import SessionRecord


class _StubTimer:
    started_at = None


class _StubAttack:
    def __init__(self):
        self.timer = _StubTimer()
        self.options = {}

    def snapshot(self):
        return {"state": "idle", "started_at": None, "stopped_at": None, "elapsed": None, "result": None}


class _StubSeverity:
    value = "medium"


class _StubModule:
    module_id = "brute_force"
    name = "Brute Force"
    scenario_id = "APP-06"
    severity = _StubSeverity()
    steps = []


class _StubTarget:
    host = "target-agent"
    port = 80


class ReportCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sid = "test-report-cache-session"
        self.rec = SessionRecord(
            session_id=self.sid,
            module=_StubModule(),
            target=_StubTarget(),
            attack=_StubAttack(),
            mission_started_at=0.0,
            mode="lab",
        )
        main._SESSIONS._sessions[self.sid] = self.rec
        self._orig_fetch = lab_progress.fetch_events
        self._orig_persist = main._SESSIONS._persist
        # Avoid touching disk / the control-api dual-write during the test.
        main._SESSIONS._persist = lambda: None

    def tearDown(self):
        main._SESSIONS._sessions.pop(self.sid, None)
        lab_progress.fetch_events = self._orig_fetch
        main._SESSIONS._persist = self._orig_persist

    async def test_reset_evidence_clears_report_cache(self):
        self.rec.report_cache = {"fake": "report"}
        # _do_reset_evidence's best-effort call to target-agent's own reset
        # endpoint isn't reachable in this test environment; fail it fast
        # instead of waiting out a real DNS timeout (it's caught either way).
        with patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("no target-agent in tests")):
            await main._do_reset_evidence(self.sid)
        self.assertIsNone(self.rec.report_cache)

    async def test_success_transition_clears_stale_report_cache(self):
        # Simulate a report that was generated (and cached) before this
        # evidence existed.
        self.rec.report_cache = {"fake": "stale-report"}
        self.rec.learning_success = False

        lab_progress.fetch_events = lambda **kwargs: [
            {"event_type": "brute_force_pattern", "module_id": "brute_force", "via": "browser", "ts": 1.0},
            {"event_type": "credential_found", "module_id": "brute_force", "via": "browser", "ts": 2.0},
        ]

        result = await main.check_progress(self.sid, mode=None, operator={"username": "tester"})

        self.assertTrue(result["success"])
        self.assertIsNone(
            self.rec.report_cache,
            "a fresh false->true success transition must invalidate a stale cached report",
        )

    async def test_no_cache_clear_when_success_was_already_true(self):
        # Once success is already true, a cached report should NOT be wiped
        # on every subsequent check-progress call (only the false->true edge).
        self.rec.learning_success = True
        self.rec.report_cache = {"fake": "already-generated-report"}

        lab_progress.fetch_events = lambda **kwargs: [
            {"event_type": "brute_force_pattern", "module_id": "brute_force", "via": "browser", "ts": 1.0},
            {"event_type": "credential_found", "module_id": "brute_force", "via": "browser", "ts": 2.0},
        ]

        await main.check_progress(self.sid, mode=None, operator={"username": "tester"})

        self.assertEqual(self.rec.report_cache, {"fake": "already-generated-report"})


if __name__ == "__main__":
    unittest.main()
