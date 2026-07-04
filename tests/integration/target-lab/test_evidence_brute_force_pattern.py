"""Regression test for evidence.py's brute_force_pattern synthesis.

Before this fix, `_detect_patterns()` hardcoded `"path": "/auth/login"` on
every synthesized brute_force_pattern event, regardless of which backend
actually saw the failures. An operator-mode brute force against
`/op/auth/login` (the harder backend - see routes_op/auth.py) would
misreport itself as a guided-mode `/auth/login` pattern, which report_agent's
brute-force summary and the operator/guided evidence split both read from.

    # from repo root
    py -m unittest discover -s tests/integration/target-lab -p test_evidence_brute_force_pattern.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/target-lab
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_TARGET_LAB_APP_DIR = os.path.join(_REPO, "apps", "target-lab", "app")
if _TARGET_LAB_APP_DIR not in sys.path:
    sys.path.insert(0, _TARGET_LAB_APP_DIR)

import evidence  # noqa: E402


class BruteForcePatternInheritanceTests(unittest.TestCase):
    def setUp(self):
        evidence.reset()

    def tearDown(self):
        evidence.reset()

    def _fail(self, ip, path, backend, via):
        evidence.record(
            "login_failed", module_id="brute_force", path=path, method="POST",
            source_ip=ip, via=via,
            extra={"backend": backend, "path": path},
        )

    def test_pattern_inherits_operator_path_and_backend(self):
        ip = "10.20.30.40"
        for _ in range(3):
            self._fail(ip, "/op/auth/login", "operator", "zap_fuzzer")

        patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
        self.assertTrue(patterns, "brute_force_pattern should synthesize after 3 failures")
        p = patterns[-1]
        self.assertEqual(p["path"], "/op/auth/login")  # NOT hardcoded /auth/login
        self.assertEqual(p["via"], "zap_fuzzer")
        self.assertEqual((p.get("extra") or {}).get("backend"), "operator")

    def test_pattern_inherits_guided_path_and_backend(self):
        ip = "10.20.30.41"
        for _ in range(3):
            self._fail(ip, "/auth/login", "guided", "browser")

        patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
        self.assertTrue(patterns)
        p = patterns[-1]
        self.assertEqual(p["path"], "/auth/login")
        self.assertEqual(p["via"], "browser")
        self.assertEqual((p.get("extra") or {}).get("backend"), "guided")

    def test_pattern_falls_back_to_default_path_when_untagged(self):
        # A login_failed event with no path (shouldn't normally happen, but
        # the fallback must not crash) still synthesizes with a sane default.
        ip = "10.20.30.42"
        for _ in range(3):
            evidence.record(
                "login_failed", module_id="brute_force", method="POST",
                source_ip=ip, via="unknown",
            )
        patterns = [e for e in evidence.list_events() if e["event_type"] == "brute_force_pattern"]
        self.assertTrue(patterns)
        self.assertEqual(patterns[-1]["path"], "/auth/login")


if __name__ == "__main__":
    unittest.main()
