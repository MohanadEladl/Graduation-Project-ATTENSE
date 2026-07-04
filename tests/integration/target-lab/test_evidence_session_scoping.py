"""Regression tests for target-agent's evidence store session scoping.

Before this fix, evidence.py had no concept of session_id at all: it's a
single in-memory ring buffer shared by every concurrent learner hitting the
same target-agent container, and reset() wiped it globally with no scoping.
These tests prove record()/list_events()/reset() now keep two sessions'
evidence from cross-contaminating.

    # from repo root (discover, not dotted import -- "target-lab" isn't a
    # valid Python module path segment convention used elsewhere either, but
    # kept consistent with the hyphenated-service test layout)
    py -m unittest discover -s tests/integration/target-lab -p test_evidence_session_scoping.py
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


class EvidenceSessionScopingTests(unittest.TestCase):
    def setUp(self):
        evidence.reset() # start every test from a clean global store

    def tearDown(self):
        evidence.reset()

    def test_list_events_scoped_to_session_excludes_other_sessions(self):
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")

        a_events = evidence.list_events(session_id="sess-A")
        b_events = evidence.list_events(session_id="sess-B")

        self.assertEqual(len(a_events), 1)
        self.assertEqual(len(b_events), 1)
        self.assertEqual(a_events[0]["session_id"], "sess-A")
        self.assertEqual(b_events[0]["session_id"], "sess-B")

    def test_list_events_without_session_id_sees_everything(self):
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")
        evidence.record("portal_visited", module_id="recon", via="unknown", session_id=None)

        all_events = evidence.list_events()
        self.assertEqual(len(all_events), 3)

    def test_reset_scoped_to_session_only_clears_that_session(self):
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")

        evidence.reset(session_id="sess-A")

        self.assertEqual(evidence.list_events(session_id="sess-A"), [])
        self.assertEqual(len(evidence.list_events(session_id="sess-B")), 1)

    def test_reset_without_session_id_clears_everything(self):
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")

        evidence.reset()

        self.assertEqual(evidence.list_events(), [])

    def test_list_events_scoped_to_session_includes_untagged_events(self):
        # AttackBox-terminal traffic (curl/nmap/hydra) has no mechanism to
        # attach a session_id, so it lands untagged (session_id=None). A
        # session-scoped query must still include it - dropping it silently
        # excluded essentially all AttackBox-driven evidence from progress
        # computation, which was the regression this test guards against.
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("command_injection_detected", module_id="cmd_injection", via="attackbox", session_id=None)

        a_events = evidence.list_events(session_id="sess-A")
        self.assertEqual(len(a_events), 2)
        event_types = {e["event_type"] for e in a_events}
        self.assertEqual(event_types, {"portal_visited", "command_injection_detected"})

    def test_list_events_scoped_to_session_still_excludes_other_tagged_session(self):
        # Untagged evidence is visible to everyone, but two *tagged* sessions
        # (e.g. two learners' own browser traffic) must still stay isolated
        # from each other - this is the core cross-session isolation
        # guarantee, preserved alongside the untagged-inclusion fix above.
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")
        evidence.record("command_injection_detected", module_id="cmd_injection", via="attackbox", session_id=None)

        a_events = evidence.list_events(session_id="sess-A")
        a_session_ids = {e["session_id"] for e in a_events}
        self.assertEqual(len(a_events), 2)
        self.assertIn("sess-A", a_session_ids)
        self.assertIn(None, a_session_ids)
        self.assertNotIn("sess-B", a_session_ids)

    def test_reset_scoped_to_session_also_clears_untagged_events(self):
        # A restart should also clear orphaned/untagged AttackBox evidence
        # instead of leaving it stuck forever, while leaving another
        # session's own tagged evidence alone.
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-A")
        evidence.record("portal_visited", module_id="recon", via="browser", session_id="sess-B")
        evidence.record("command_injection_detected", module_id="cmd_injection", via="attackbox", session_id=None)

        evidence.reset(session_id="sess-A")

        self.assertEqual(evidence.list_events(session_id="sess-A"), [])
        remaining = evidence.list_events()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["session_id"], "sess-B")

    def test_derived_events_inherit_session_id(self):
        # 3+ failed logins from the same source_ip within 5 minutes should
        # synthesize brute_force_pattern, tagged with the triggering events'
        # session_id so it's still scoped correctly.
        for _ in range(3):
            evidence.record(
                "login_failed", module_id="brute_force", via="browser",
                source_ip="10.0.0.5", session_id="sess-A",
            )
        derived = [e for e in evidence.list_events(session_id="sess-A")
                   if e["event_type"] == "brute_force_pattern"]
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0]["session_id"], "sess-A")


if __name__ == "__main__":
    unittest.main()
