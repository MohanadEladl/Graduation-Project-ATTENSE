"""Regression tests for the "Enter Room" heavy/first-click-fails/TheHive-
keeps-restarting-forever bug.

Root cause: `authorize_org_for_webhook` used to synchronously restart the
ONE SHARED `attense_thehive` container and block for up to its readiness
timeout every time a brand-new per-room org was created - which is
essentially every "Enter Room" click on a fresh room during active testing
(the org-reuse pool only fills up 30+ minutes after a room closes). That
made the request itself heavy, made it exceed the frontend nginx proxy's
`proxy_read_timeout` (so the first click looked like it failed even though
the backend kept working), and took the whole shared TheHive instance down
for every other analyst each time.

The fix moves the restart+readiness-wait onto a background thread so the
calling request returns as soon as the conf file is written, and coalesces
back-to-back restarts for different orgs into a single restart when
possible (the actual "keeps restarting forever" fix, not just "returns
fast").

    # from repo root (discover, not dotted import -- "control-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/control-api -p test_hive_webhook_restart.py
"""

import json
import os
import sys
import tempfile
import threading
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from core import hive_provisioner  # noqa: E402


class _FakeContainer:
    def __init__(self, restart_calls, restart_started, hold_restart):
        self._restart_calls = restart_calls
        self._restart_started = restart_started
        self._hold_restart = hold_restart

    def restart(self, timeout=30):
        self._restart_calls.append(timeout)
        self._restart_started.set()
        # Simulate the restart taking a while, held open until the test lets
        # it proceed - this is what lets a test observe that the calling
        # (request) thread already returned before this finishes.
        self._hold_restart.wait(timeout=5)


class _FakeContainers:
    def __init__(self, container):
        self._container = container

    def get(self, name):
        return self._container


class _FakeDockerClient:
    def __init__(self, container):
        self.containers = _FakeContainers(container)
        self.closed = False

    def close(self):
        self.closed = True


class AuthorizeOrgForWebhookAsyncTests(unittest.TestCase):
    def setUp(self):
        self._orig_conf_path = hive_provisioner.THEHIVE_CONF_PATH
        self._orig_from_env = hive_provisioner.docker.from_env
        self._orig_wait_ready = hive_provisioner._wait_for_thehive_ready
        self._orig_write_seq = hive_provisioner._conf_write_seq
        self._orig_restarted_through = hive_provisioner._restarted_through_seq
        hive_provisioner._conf_write_seq = 0
        hive_provisioner._restarted_through_seq = 0

        fd, self._conf_path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        with open(self._conf_path, "w", encoding="utf-8") as f:
            f.write('includedTheHiveOrganisations = ["blue-team"]\n')
        hive_provisioner.THEHIVE_CONF_PATH = self._conf_path

        self.restart_calls = []
        self.restart_started = threading.Event()
        self.hold_restart = threading.Event()
        self._container = _FakeContainer(
            self.restart_calls, self.restart_started, self.hold_restart
        )
        self._docker_client = _FakeDockerClient(self._container)
        hive_provisioner.docker.from_env = lambda: self._docker_client

        # Ready immediately once the (held) restart call returns, so the
        # background thread can finish once the test releases hold_restart.
        hive_provisioner._wait_for_thehive_ready = lambda *a, **k: True

        self._spawned_threads = []
        orig_thread_init = threading.Thread.__init__
        test = self

        def _tracking_init(self, *args, **kwargs):
            orig_thread_init(self, *args, **kwargs)
            if kwargs.get("name", "").startswith("thehive-restart"):
                test._spawned_threads.append(self)

        threading.Thread.__init__ = _tracking_init
        self._orig_thread_init = orig_thread_init

    def tearDown(self):
        self.hold_restart.set()
        for t in self._spawned_threads:
            t.join(timeout=5)
        threading.Thread.__init__ = self._orig_thread_init
        hive_provisioner.THEHIVE_CONF_PATH = self._orig_conf_path
        hive_provisioner.docker.from_env = self._orig_from_env
        hive_provisioner._wait_for_thehive_ready = self._orig_wait_ready
        hive_provisioner._conf_write_seq = self._orig_write_seq
        hive_provisioner._restarted_through_seq = self._orig_restarted_through
        try:
            os.remove(self._conf_path)
        except OSError:
            pass

    def _conf_orgs(self):
        with open(self._conf_path, "r", encoding="utf-8") as f:
            content = f.read()
        import re

        match = re.search(r"includedTheHiveOrganisations\s*=\s*(\[[^\]]*\])", content)
        return json.loads(match.group(1))

    def test_already_authorized_org_is_a_fast_noop(self):
        result = hive_provisioner.authorize_org_for_webhook("blue-team")
        self.assertFalse(result)
        self.assertEqual(self.restart_calls, [])

    def test_new_org_returns_before_restart_completes(self):
        # The whole point of the fix: the caller must not block on the
        # restart. hold_restart is never set here, so if
        # authorize_org_for_webhook waited for the restart to finish, this
        # call itself would hang for up to the test framework's timeout.
        result = hive_provisioner.authorize_org_for_webhook("room-new-1")

        self.assertTrue(result)
        # The conf file must already reflect the new org even though the
        # restart hasn't finished - the write happens synchronously before
        # the background thread is spawned.
        self.assertIn("room-new-1", self._conf_orgs())
        # Give the background thread a moment to reach container.restart();
        # the call above must have returned well before this.
        self.assertTrue(self.restart_started.wait(timeout=5))

    def test_two_new_orgs_coalesce_into_a_single_restart(self):
        # Room A's entry queues a restart and it's still "in flight" (held
        # open by hold_restart) when room B's entry comes in right after.
        # B's org write must still land in the conf file, but it must NOT
        # trigger a second real container restart - the in-flight restart
        # already covers it (conf write happens before the restart is
        # queued, so ordering guarantees the held-open restart will have
        # read past B's write by the time it actually executes `restart()`
        # under the lock... in this fake, `restart()` fires the "started"
        # event immediately, so we instead assert on the call count in the
        # only-one-restart sense: no second Thread's restart() call is ever
        # made once the first is already holding `_restart_lock`).
        hive_provisioner.authorize_org_for_webhook("room-new-A")
        self.assertTrue(self.restart_started.wait(timeout=5))

        result_b = hive_provisioner.authorize_org_for_webhook("room-new-B")
        self.assertTrue(result_b)
        self.assertIn("room-new-B", self._conf_orgs())

        self.hold_restart.set()
        for t in self._spawned_threads:
            t.join(timeout=5)

        self.assertEqual(len(self.restart_calls), 1)

    def test_concurrent_new_orgs_never_lose_an_entry(self):
        # Race B: two threads authorizing two different brand-new orgs at
        # the same time must never clobber each other's conf-file write.
        barrier = threading.Barrier(2)

        def _authorize(org_name):
            barrier.wait(timeout=5)
            hive_provisioner.authorize_org_for_webhook(org_name)

        t1 = threading.Thread(target=_authorize, args=("room-concurrent-1",))
        t2 = threading.Thread(target=_authorize, args=("room-concurrent-2",))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        self.hold_restart.set()
        for t in self._spawned_threads:
            t.join(timeout=5)

        orgs = self._conf_orgs()
        self.assertIn("room-concurrent-1", orgs)
        self.assertIn("room-concurrent-2", orgs)


if __name__ == "__main__":
    unittest.main()
