"""Regression tests for mission_store.py's dead-code-after-early-return bug.

Every guard-clause function in this file had its "normal path" body
accidentally indented one level too deep, nested inside the early-return
branch -- so record_mission_snapshot(), record_room_participant(),
record_blue_action(), record_red_action(), list_missions_for_user(), and
several helpers were unreachable no-ops in the case that actually matters
(a valid session_key/username/room, i.e. every real call). These tests use a
fake DB connection/cursor (no real Postgres needed) to prove the SQL paths
now actually execute.

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_mission_store.py
"""

import os
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from core import mission_store


class _FakeCursor:
    """Records every execute() call; returns queued fetchone/fetchall results
    in call order so tests can control exactly what each SELECT sees."""

    def __init__(self, results=None):
        self.executed = []
        self._results = list(results or [])

    def execute(self, query, params=None):
        self.executed.append((" ".join(query.split()), params))

    def _next(self, default):
        return self._results.pop(0) if self._results else default

    def fetchone(self):
        return self._next(None)

    def fetchall(self):
        return self._next([])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patched_connection(cursor):
    @contextmanager
    def _conn():
        yield _FakeConn(cursor)
    return _conn


class RecordMissionSnapshotTests(unittest.TestCase):
    """record_mission_snapshot() with a real session_key must actually reach
    the INSERT INTO "MissionAttempt" statement, not silently no-op."""

    def setUp(self):
        self.cursor = _FakeCursor()
        self._orig_connection = mission_store.connection
        mission_store.connection = _patched_connection(self.cursor)

    def tearDown(self):
        mission_store.connection = self._orig_connection

    def test_valid_session_key_reaches_insert(self):
        mission_store.record_mission_snapshot({
            "session_id": "sess-1",
            "module_id": "brute_force",
            "scenario_id": "APP-06",
            "learning_success": True,
            "learning_progress_percent": 100,
        })
        insert_queries = [q for q, _ in self.cursor.executed if 'INSERT INTO "MissionAttempt"' in q]
        self.assertEqual(len(insert_queries), 1,
                          "record_mission_snapshot must execute exactly one MissionAttempt insert "
                          "for a valid session_key")

    def test_missing_session_key_is_a_genuine_noop(self):
        mission_store.record_mission_snapshot({"module_id": "brute_force"})
        self.assertEqual(self.cursor.executed, [],
                          "a snapshot with no session_id/session_key should still no-op")


class ListMissionsForUserTests(unittest.TestCase):
    """list_missions_for_user(completed=None) -- the plain GET /api/missions
    case -- must return rows, not fall off the end and return None."""

    def setUp(self):
        row = {
            "session_key": "sess-1",
            "room_key": "room-1",
            "module_id": "brute_force",
            "scenario_key": "APP-06",
            "learning_success": True,
            "progress_percent": 100,
            "payload": {},
            "room": None,
        }
        self.cursor = _FakeCursor(results=[[row]])
        self._orig_connection = mission_store.connection
        mission_store.connection = _patched_connection(self.cursor)

    def tearDown(self):
        mission_store.connection = self._orig_connection

    def test_completed_none_returns_rows_not_none(self):
        result = mission_store.list_missions_for_user("alice", completed=None)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["session_id"], "sess-1")
        self.assertEqual(result[0]["learning_success"], True)


class PureHelperTests(unittest.TestCase):
    """No DB needed -- these are the plain data-shaping helpers that had the
    same dead-code-after-return defect."""

    def test_epoch_to_timestamptz_converts_numeric(self):
        # 2025-01-01T00:00:00+00:00 in epoch seconds.
        expected = datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat()
        self.assertEqual(mission_store._epoch_to_timestamptz(1735689600.0), expected)

    def test_epoch_to_timestamptz_passes_through_strings(self):
        self.assertEqual(mission_store._epoch_to_timestamptz("2026-01-01T00:00:00+00:00"),
                          "2026-01-01T00:00:00+00:00")

    def test_epoch_to_timestamptz_none_or_empty(self):
        self.assertIsNone(mission_store._epoch_to_timestamptz(None))
        self.assertIsNone(mission_store._epoch_to_timestamptz(""))

    def test_mission_from_row_always_returns_payload(self):
        # No "room" key at all -- must still return the payload, not None.
        row = {
            "payload": {"foo": "bar"},
            "session_key": "sess-1",
            "room_key": None,
            "module_id": "recon",
            "scenario_key": "APP-01",
            "learning_success": False,
            "progress_percent": 40,
        }
        result = mission_store._mission_from_row(row)
        self.assertIsNotNone(result)
        self.assertEqual(result["foo"], "bar")
        self.assertEqual(result["session_id"], "sess-1")

    def test_mission_from_row_attaches_room_when_present(self):
        row = {
            "payload": {},
            "session_key": "sess-1",
            "room_key": "room-1",
            "module_id": "recon",
            "scenario_key": "APP-01",
            "learning_success": False,
            "progress_percent": 40,
            "room": {"scenario_id": "APP-01"},
        }
        result = mission_store._mission_from_row(row)
        self.assertEqual(result["room"], {"scenario_id": "APP-01"})


if __name__ == "__main__":
    unittest.main()
