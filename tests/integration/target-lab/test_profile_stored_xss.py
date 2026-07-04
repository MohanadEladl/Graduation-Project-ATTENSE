"""Tests for the session-scoped, self-resetting stored XSS on the profile
email field (fixes the xss module's previously-dead `stored_attempt`
variant, which had no real vulnerability to trigger against).

A planted payload is visible only to the session that planted it (persists
across that session's own page refreshes), never leaks to another
concurrent session, and reverts to normal once that session's evidence is
reset (mission finish/restart).

    # from repo root
    py -m unittest discover -s tests/integration/target-lab -p test_profile_stored_xss.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__)) # tests/integration/target-lab
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_TARGET_LAB_APP_DIR = os.path.join(_REPO, "apps", "target-lab", "app")
if _TARGET_LAB_APP_DIR not in sys.path:
    sys.path.insert(0, _TARGET_LAB_APP_DIR)

import evidence
import main as target_main
from routes.profile import _PROFILES, _stored_xss_by_session

_PAYLOAD = "<script>alert(1)</script>@evil.lab"


class ProfileStoredXssTests(unittest.TestCase):
    def setUp(self):
        target_main.app.testing = True
        evidence.reset()
        _stored_xss_by_session.clear()
        # Guard against cross-test bleed into the shared account dict.
        self._orig_guest_email = _PROFILES["guest"]["email"]

    def tearDown(self):
        evidence.reset()
        _stored_xss_by_session.clear()
        _PROFILES["guest"]["email"] = self._orig_guest_email

    def test_payload_post_stashes_by_session_and_does_not_touch_shared_profile(self):
        client = target_main.app.test_client()
        resp = client.post("/profile/update?attense_sid=sess-A", data={"email": _PAYLOAD})
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(_stored_xss_by_session.get("sess-A"), _PAYLOAD)
        self.assertEqual(_PROFILES["guest"]["email"], self._orig_guest_email)

        events = evidence.list_events(session_id="sess-A")
        event_types = {e["event_type"] for e in events}
        self.assertIn("xss_payload_observed", event_types)
        self.assertNotIn("profile_changed_without_csrf", event_types)

    def test_same_session_sees_payload_persist_across_refresh(self):
        client = target_main.app.test_client()
        client.post("/profile/update?attense_sid=sess-A", data={"email": _PAYLOAD})

        resp = client.get("/profile/")
        body = resp.get_data(as_text=True)
        self.assertIn(_PAYLOAD, body)

        events = evidence.list_events(session_id="sess-A")
        self.assertIn("reflected_input_detected", {e["event_type"] for e in events})

    def test_different_session_does_not_see_payload(self):
        client_a = target_main.app.test_client()
        client_b = target_main.app.test_client()
        client_a.post("/profile/update?attense_sid=sess-A", data={"email": _PAYLOAD})

        resp = client_b.get("/profile/?attense_sid=sess-B")
        body = resp.get_data(as_text=True)
        self.assertNotIn(_PAYLOAD, body)
        self.assertIn("guest@lab.local", body)

    def test_reset_reverts_session_to_normal(self):
        client = target_main.app.test_client()
        client.post("/profile/update?attense_sid=sess-A", data={"email": _PAYLOAD})

        resp = client.post("/lab/events/reset?session_id=sess-A")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("sess-A", _stored_xss_by_session)

        resp = client.get("/profile/")
        body = resp.get_data(as_text=True)
        self.assertNotIn(_PAYLOAD, body)

    def test_normal_email_update_unaffected(self):
        client = target_main.app.test_client()
        resp = client.post("/profile/update?attense_sid=sess-A", data={"email": "new@lab.local"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(_PROFILES["guest"]["email"], "new@lab.local")
        self.assertNotIn("sess-A", _stored_xss_by_session)
        events = evidence.list_events(session_id="sess-A")
        self.assertIn("profile_changed_without_csrf", {e["event_type"] for e in events})


if __name__ == "__main__":
    unittest.main()
