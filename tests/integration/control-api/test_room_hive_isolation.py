"""Regression tests for the TheHive shared-org isolation leak.

Before this fix, `ensure_member_hive_access(username)` silently (re-)enrolled
every Blue/SOC user into one pre-seeded, platform-wide shared TheHive org
literally named "blue-team" on nearly every room interaction - including just
viewing a room's detail page. Since TheHive ties a user's API key/login to
whichever org they were FIRST created in, this stuck most users in
"blue-team" forever instead of their actual room's own org, breaking the
per-room isolation `_ensure_room_hive` was supposed to provide.

`ensure_member_hive_login(room_id, username)` replaces it: it only ever
touches THIS room's own org (`room["hive_org"]`), and no-ops entirely (no
fallback org) when the room doesn't have one yet.

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_room_hive_isolation.py
"""

import os
import sys
import unittest
from unittest.mock import call

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from core import room_manager  # noqa: E402
from core import hive_provisioner  # noqa: E402


class EnsureMemberHiveLoginTests(unittest.TestCase):
    def setUp(self):
        self._orig_load_room = room_manager._load_room
        self._orig_get_user = room_manager.user_store.get_user_by_username
        self._orig_create_user_in_org = hive_provisioner.create_user_in_org
        self.create_user_calls = []

        def _fake_create_user_in_org(org_name, username, attense_role, renew_key=True):
            self.create_user_calls.append(
                call(org_name, username, attense_role=attense_role, renew_key=renew_key)
            )
            return "fake-api-key"

        hive_provisioner.create_user_in_org = _fake_create_user_in_org
        room_manager.user_store.get_user_by_username = lambda username: None

    def tearDown(self):
        room_manager._load_room = self._orig_load_room
        room_manager.user_store.get_user_by_username = self._orig_get_user
        hive_provisioner.create_user_in_org = self._orig_create_user_in_org

    def test_legacy_shared_org_function_is_gone(self):
        # The confirmed root cause of the isolation leak must be fully
        # removed, not just unused - so nothing can call back into it.
        self.assertFalse(hasattr(room_manager, "ensure_member_hive_access"))

    def test_provisions_into_the_rooms_own_org_not_a_shared_one(self):
        room_manager._load_room = lambda room_id: {
            "room_id": room_id, "hive_org": "room-X",
        }

        room_manager.ensure_member_hive_login("room-X-id", "analyst-b")

        self.assertEqual(len(self.create_user_calls), 1)
        org_arg = self.create_user_calls[0].args[0]
        username_arg = self.create_user_calls[0].args[1]
        self.assertEqual(org_arg, "room-X")
        self.assertEqual(username_arg, "analyst-b")
        self.assertNotEqual(org_arg, "blue-team")

    def test_room_with_no_org_yet_gets_no_credentials_and_no_call(self):
        # Nobody has entered this room yet (_ensure_room_hive never ran), so
        # there is genuinely no room-specific org to log into. Must NOT fall
        # back to any shared org - that fallback is exactly the leak.
        room_manager._load_room = lambda room_id: {"room_id": room_id, "hive_org": None}

        room_manager.ensure_member_hive_login("room-Y-id", "analyst-c")

        self.assertEqual(self.create_user_calls, [])

    def test_missing_room_is_a_safe_noop(self):
        def _raise_not_found(room_id):
            raise ValueError(f"Room not found: {room_id}")

        room_manager._load_room = _raise_not_found

        try:
            room_manager.ensure_member_hive_login("no-such-room", "analyst-d")
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"ensure_member_hive_login raised for a missing room: {exc}")
        self.assertEqual(self.create_user_calls, [])

    def test_provisioning_failure_is_swallowed_best_effort(self):
        room_manager._load_room = lambda room_id: {
            "room_id": room_id, "hive_org": "room-Z",
        }

        def _boom(*a, **k):
            raise RuntimeError("TheHive unreachable")

        hive_provisioner.create_user_in_org = _boom

        try:
            room_manager.ensure_member_hive_login("room-Z-id", "analyst-e")
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"ensure_member_hive_login must be best-effort, raised: {exc}")

    def test_two_rooms_provision_into_two_different_orgs(self):
        rooms = {
            "room-A-id": {"room_id": "room-A-id", "hive_org": "room-A"},
            "room-B-id": {"room_id": "room-B-id", "hive_org": "room-B"},
        }
        room_manager._load_room = lambda room_id: rooms[room_id]

        room_manager.ensure_member_hive_login("room-A-id", "viewer")
        room_manager.ensure_member_hive_login("room-B-id", "viewer")

        orgs_used = [c.args[0] for c in self.create_user_calls]
        self.assertEqual(orgs_used, ["room-A", "room-B"])
        self.assertEqual(len(set(orgs_used)), 2)


if __name__ == "__main__":
    unittest.main()
