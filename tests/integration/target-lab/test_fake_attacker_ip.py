"""Regression tests for target-agent's fake attacker IP generation.

Before this fix, every observable/log line recorded `request.remote_addr`,
which is unconditionally `127.0.0.1` (target-agent's own nginx always proxies
to Flask over loopback) - so TheHive never showed a plausible attacker IP.
`fake_attacker_ip()` replaces it with a deterministic, non-routable
(RFC 5737 TEST-NET) address derived from the learner's session id, so the
same learner's traffic always correlates to the same fake IP and two
concurrent learners never collide.

    # from repo root
    py -m unittest discover -s tests/integration/target-lab -p test_fake_attacker_ip.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/target-lab
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_TARGET_LAB_APP_DIR = os.path.join(_REPO, "apps", "target-lab", "app")
if _TARGET_LAB_APP_DIR not in sys.path:
    sys.path.insert(0, _TARGET_LAB_APP_DIR)

import main as target_main  # noqa: E402

_TEST_NET_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


class FakeAttackerIpTests(unittest.TestCase):
    def setUp(self):
        target_main.app.testing = True
        target_main._fake_ip_cache.clear()

    def tearDown(self):
        target_main._fake_ip_cache.clear()

    def _ip_for(self, sid=None, headers=None):
        path = f"/?attense_sid={sid}" if sid else "/"
        with target_main.app.test_request_context(path, headers=headers or {}):
            return target_main.fake_attacker_ip()

    def test_ip_is_always_in_a_test_net_range(self):
        for sid in ("sess-A", "sess-B", "sess-C", "sess-D", "sess-E"):
            ip = self._ip_for(sid)
            self.assertTrue(
                any(ip.startswith(p) for p in _TEST_NET_PREFIXES),
                f"{ip} is not in a TEST-NET range",
            )
            octet = int(ip.rsplit(".", 1)[1])
            self.assertGreaterEqual(octet, 1)
            self.assertLessEqual(octet, 254)

    def test_same_session_always_gets_the_same_ip(self):
        first = self._ip_for("sess-same")
        second = self._ip_for("sess-same")
        third = self._ip_for("sess-same")
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_different_sessions_get_different_ips(self):
        # Not a mathematical guarantee (SHA-256 could theoretically collide),
        # but for these fixed inputs the derived IPs are known to differ -
        # this is the real-world "two concurrent learners" case.
        ip_a = self._ip_for("sess-alpha")
        ip_b = self._ip_for("sess-bravo")
        self.assertNotEqual(ip_a, ip_b)

    def test_no_session_id_falls_back_without_raising(self):
        # Bare AttackBox curl/nmap traffic has no attense_sid at all.
        try:
            ip = self._ip_for(sid=None)
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"fake_attacker_ip() raised with no session id: {exc}")
        self.assertTrue(any(ip.startswith(p) for p in _TEST_NET_PREFIXES))

    def test_outside_request_context_never_raises(self):
        # No Flask request context at all (e.g. called from a background job).
        try:
            ip = target_main.fake_attacker_ip()
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"fake_attacker_ip() raised outside a request context: {exc}")
        self.assertEqual(ip, "192.0.2.1")

    def test_result_is_cached_across_calls(self):
        with target_main.app.test_request_context("/?attense_sid=sess-cache"):
            first = target_main.fake_attacker_ip()
            self.assertIn("sid:sess-cache", target_main._fake_ip_cache)
            # Corrupt the cache entry to prove the second call reuses it
            # instead of recomputing.
            target_main._fake_ip_cache["sid:sess-cache"] = "203.0.113.99"
            second = target_main.fake_attacker_ip()
        self.assertEqual(second, "203.0.113.99")
        self.assertNotEqual(first, second)  # sanity: the corruption took effect

    def test_no_session_id_still_distinguishes_by_remote_addr_and_channel(self):
        # Two different (remote_addr, via) combos with no session id shouldn't
        # be forced to collide just because both lack a session id.
        with target_main.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "10.0.0.5"}
        ):
            ip_1 = target_main.fake_attacker_ip()
        with target_main.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "10.0.0.6"}
        ):
            ip_2 = target_main.fake_attacker_ip()
        self.assertNotEqual(ip_1, ip_2)


if __name__ == "__main__":
    unittest.main()
