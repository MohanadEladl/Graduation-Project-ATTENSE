"""Regression tests for route_security.py's has_command_output_indicator.

Before this fix, the predicate only recognized `id`/`cat /etc/passwd`/
`ls -la`/`uname -a` output - not `whoami`, `hostname`, `pwd`, `env`, or
`ifconfig`/`ip addr`, all common RCE-proof commands (including the ones the
app's own cmd_injection variants suggest). A learner whose injection
genuinely worked but used one of these commands got zero confirming
evidence.

    # from repo root
    py -m unittest discover -s tests/integration/target-lab -p test_route_security.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__)) # tests/integration/target-lab
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_TARGET_LAB_APP_DIR = os.path.join(_REPO, "apps", "target-lab", "app")
if _TARGET_LAB_APP_DIR not in sys.path:
    sys.path.insert(0, _TARGET_LAB_APP_DIR)

import route_security as rs

_PLAIN_PING = (
    "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
    "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n"
    "64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.052 ms\n"
    "\n"
    "--- 127.0.0.1 ping statistics ---\n"
    "2 packets transmitted, 2 received, 0% packet loss, time 1023ms\n"
    "rtt min/avg/max/mdev = 0.045/0.048/0.052/0.007 ms\n"
)


class CommandOutputIndicatorTests(unittest.TestCase):
    def test_plain_ping_output_is_not_flagged(self):
        self.assertFalse(rs.has_command_output_indicator(_PLAIN_PING))

    def test_ping_error_output_is_not_flagged(self):
        self.assertFalse(rs.has_command_output_indicator("ping: unknown host badhost.invalid\n"))

    def test_id_output_still_flagged(self):
        # Pre-existing marker - regression guard that broadening the
        # predicate didn't accidentally narrow it.
        self.assertTrue(rs.has_command_output_indicator(_PLAIN_PING + "uid=0(root) gid=0(root) groups=0(root)\n"))

    def test_whoami_output_is_flagged(self):
        self.assertTrue(rs.has_command_output_indicator(_PLAIN_PING + "root\n"))

    def test_hostname_output_is_flagged(self):
        self.assertTrue(rs.has_command_output_indicator(_PLAIN_PING + rs._CONTAINER_HOSTNAME + "\n"))

    def test_pwd_output_is_flagged(self):
        self.assertTrue(rs.has_command_output_indicator(_PLAIN_PING + "/app\n"))

    def test_env_output_is_flagged(self):
        self.assertTrue(rs.has_command_output_indicator(
            _PLAIN_PING + "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
        ))

    def test_ifconfig_output_is_flagged(self):
        self.assertTrue(rs.has_command_output_indicator(
            _PLAIN_PING + "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n"
            "        inet 172.18.0.5  netmask 255.255.0.0\n"
        ))

    def test_empty_output_is_not_flagged(self):
        self.assertFalse(rs.has_command_output_indicator(""))
        self.assertFalse(rs.has_command_output_indicator(None))


if __name__ == "__main__":
    unittest.main()
