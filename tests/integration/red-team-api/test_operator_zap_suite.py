"""Regression tests for operator_api.py's hardened command validator and the
ZAP Fuzzer/Repeater/Browser-proxy suite ported in from the
feature/attacker-activity-log branch.

Context: the ported branch's own command executor was fully tokenized with no
shell, which would have rejected the curriculum's real ideal_commands (loops,
variable assignment, curl|grep pipes, and the cmd_injection module's
$(id)/backtick PAYLOAD VALUES sent as literal curl arguments). The merged
design keeps `bash -c` execution (so those keep working) but adds:
  - an enforced exec timeout (previously a dead constant)
  - a tool-allowlist gate for "simple" TOOL-arg... commands only (loops,
    comments, and VAR=value assignments skip it and rely on the pre-existing
    BLOCKED_PATTERNS blocklist alone, unchanged)
This suite pins that exact split, plus the new ZAP normalize/history/
repeater/fuzzer/browse-through-zap functions.

    # from repo root (discover, not dotted import -- "red-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/red-team-api -p test_operator_zap_suite.py
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/red-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_RED_TEAM_DIR = os.path.join(_REPO, "apps", "red-team-api")
if _RED_TEAM_DIR not in sys.path:
    sys.path.insert(0, _RED_TEAM_DIR)

from backend import operator_api as op  # noqa: E402
from backend import lab_progress  # noqa: E402


class ValidateCommandCurriculumCompatibilityTests(unittest.TestCase):
    """Every real (non-continuation-fragment) ideal_command across every
    module/variant must still validate cleanly - the whole point of keeping
    bash -c instead of adopting the branch's no-shell tokenized executor."""

    def test_every_standalone_ideal_command_passes(self):
        failures = []
        for module_id, variants in lab_progress.MODULE_VARIANTS.items():
            for variant_id, variant in variants.items():
                continues_from_prev = False
                for cmd in variant.get("ideal_commands", []):
                    stripped = cmd.strip()
                    is_continuation = continues_from_prev
                    continues_from_prev = stripped.endswith("\\")
                    if not stripped or is_continuation or continues_from_prev:
                        continue  # backslash-continuation fragment, not standalone
                    err = op.validate_command(stripped)
                    if err:
                        failures.append((module_id, variant_id, stripped, err))
        self.assertEqual(failures, [])

    def test_cmd_injection_payload_values_are_not_treated_as_shell_syntax(self):
        # The core of the cmd_injection module: $(...)/`...`/; appear as
        # literal characters inside a curl argument VALUE, not as real shell
        # syntax (bash -c never sees them as a separate token here since
        # they're glued to other characters, not surrounded by whitespace).
        cmd = "curl -s -G --data-urlencode 'host=$(id)' http://target-agent/system/ping"
        self.assertIsNone(op.validate_command(cmd))

    def test_pipes_still_work_since_bash_c_provides_a_real_shell(self):
        cmd = "curl -s http://target-agent/ | grep -E '<!--|Server' -i"
        self.assertIsNone(op.validate_command(cmd))


class ValidateCommandHardeningTests(unittest.TestCase):
    def test_unapproved_tool_is_blocked(self):
        self.assertIsNotNone(op.validate_command("vi /etc/passwd"))
        self.assertIsNotNone(op.validate_command("ssh user@target-agent"))

    def test_approved_tool_against_local_target_is_allowed(self):
        self.assertIsNone(op.validate_command("nmap -p 1-1000 target-agent"))

    def test_external_target_still_blocked(self):
        self.assertIsNotNone(op.validate_command("curl http://evil.com/"))
        self.assertIsNotNone(op.validate_command("nmap 8.8.8.8"))

    def test_command_chaining_still_blocked_by_existing_patterns(self):
        self.assertIsNotNone(op.validate_command("curl http://target-agent/ ; rm -rf /"))
        self.assertIsNotNone(op.validate_command("sudo whoami"))
        self.assertIsNotNone(op.validate_command("docker ps"))

    def test_scripted_loop_examples_skip_the_tool_allowlist(self):
        # A loop-based example (curriculum's brute_force wordlist scripts)
        # starts with a shell keyword, not a tool name - it must not be
        # rejected merely for that shape (only BLOCKED_PATTERNS applies).
        cmd = "for u in $(cat /lab/users.txt); do echo $u; done"
        self.assertIsNone(op.validate_command(cmd))

    def test_variable_assignment_examples_skip_the_tool_allowlist(self):
        cmd = "WORDS=/wordlists/rockyou-mini.txt"
        self.assertIsNone(op.validate_command(cmd))


class ExecTimeoutWiringTests(unittest.TestCase):
    def test_exec_in_attackbox_wraps_with_enforced_timeout(self):
        captured = {}

        class FakeContainer:
            def exec_run(self, cmd, demux=False, socket=False):
                captured["cmd"] = cmd
                return (0, b"ok")

        class FakeClient:
            class containers:
                @staticmethod
                def get(name):
                    return FakeContainer()

        with patch.object(op, "_docker_client", return_value=FakeClient()):
            result = op.exec_in_attackbox("curl http://target-agent/")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(captured["cmd"][0], "timeout")
        self.assertIn(f"{op.MAX_EXEC_TIMEOUT}s", captured["cmd"])
        self.assertIn("bash", captured["cmd"])
        self.assertIn("-c", captured["cmd"])


class NormalizeZapTargetPathTests(unittest.TestCase):
    def test_relative_path_passthrough(self):
        self.assertEqual(op.normalize_zap_target_path("/search?q=1"), "/search?q=1")

    def test_bare_path_gets_leading_slash(self):
        self.assertEqual(op.normalize_zap_target_path("search"), "/search")

    def test_full_local_url_is_reduced_to_path(self):
        self.assertEqual(op.normalize_zap_target_path("http://target-agent/profile/"), "/profile/")

    def test_external_url_is_rejected(self):
        with self.assertRaises(ValueError):
            op.normalize_zap_target_path("http://evil.com/x")

    def test_protocol_relative_url_is_rejected(self):
        with self.assertRaises(ValueError):
            op.normalize_zap_target_path("//evil.com/x")

    def test_crlf_injection_is_rejected(self):
        with self.assertRaises(ValueError):
            op.normalize_zap_target_path("/search\r\nX-Injected: 1")


class ZapBrowseTargetPathTests(unittest.TestCase):
    def test_empty_path_maps_to_operator_root(self):
        self.assertEqual(op._zap_browse_target_path(""), "/op/")

    def test_bare_path_gets_operator_prefix(self):
        self.assertEqual(op._zap_browse_target_path("search"), "/op/search")

    def test_app_level_prefixes_stay_unprefixed(self):
        self.assertEqual(op._zap_browse_target_path("lab/__attense_trace.js"), "/lab/__attense_trace.js")

    def test_smuggled_scheme_is_rejected(self):
        self.assertIsNone(op._zap_browse_target_path("http://evil.com/"))
        self.assertIsNone(op._zap_browse_target_path("//evil.com/"))


class ZapRepeaterSendTests(unittest.TestCase):
    def setUp(self):
        op._evidence_log.clear()
        op._zap_history.clear()

    def _fake_zap_response(self, body="hello world", status="200 OK"):
        payload = json.dumps({
            "sendRequest": [{"responseHeader": f"HTTP/1.1 {status}", "responseBody": body}]
        }).encode("utf-8")

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return payload

        return FakeResp()

    def test_repeater_records_history_and_evidence_tagged_to_session(self):
        with patch.object(op.urllib.request, "urlopen", return_value=self._fake_zap_response()):
            result = op.zap_repeater_send("GET", "/search?q=x", session_id="sess-A", module_id="xss")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["response_status"], "200")
        self.assertEqual(len(op._zap_history), 1)
        self.assertEqual(op._zap_history[-1]["session_id"], "sess-A")
        self.assertEqual(len(op._evidence_log), 1)
        self.assertEqual(op._evidence_log[-1]["session_id"], "sess-A")
        self.assertEqual(op._evidence_log[-1]["event_type"], "zap_repeater_request")

    def test_repeater_blocks_external_target(self):
        result = op.zap_repeater_send("GET", "http://evil.com/", session_id="sess-A")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(op._zap_history, [])


class ZapFuzzerSendTests(unittest.TestCase):
    def setUp(self):
        op._evidence_log.clear()
        op._zap_history.clear()

    def _fake_zap_response_sequence(self, bodies_and_statuses):
        responses = iter(bodies_and_statuses)

        def _urlopen(*_a, **_k):
            body, status = next(responses)
            payload = json.dumps({
                "sendRequest": [{"responseHeader": f"HTTP/1.1 {status}", "responseBody": body}]
            }).encode("utf-8")

            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        return _urlopen

    def test_fuzzer_flags_grep_match_as_the_hit(self):
        # Username enumeration: "admin" gets "Incorrect password" back,
        # "nosuchuser" gets a different (non-matching) body.
        urlopen_fn = self._fake_zap_response_sequence([
            ("Incorrect password", "401 UNAUTHORIZED"),
            ("Account not found", "401 UNAUTHORIZED"),
        ])
        with patch.object(op.urllib.request, "urlopen", side_effect=urlopen_fn):
            result = op.zap_fuzzer_send(
                "POST", "/auth/login", "username=§FUZZ§&password=x",
                marker="§FUZZ§", payloads=["admin", "nosuchuser"],
                grep="Incorrect password", session_id="sess-B",
            )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["results"]), 2)
        admin_row = result["results"][0]
        other_row = result["results"][1]
        self.assertTrue(admin_row["grep_match"])
        self.assertTrue(admin_row["hit"])
        self.assertFalse(other_row["grep_match"])
        self.assertFalse(other_row["hit"])

    def test_fuzzer_caps_payload_count(self):
        many_payloads = [str(i) for i in range(op.FUZZER_MAX_PAYLOADS + 50)]
        urlopen_fn = self._fake_zap_response_sequence(
            [("body", "200 OK")] * op.FUZZER_MAX_PAYLOADS
        )
        with patch.object(op.urllib.request, "urlopen", side_effect=urlopen_fn):
            result = op.zap_fuzzer_send(
                "POST", "/search", "q=§§", marker="§§", payloads=many_payloads,
            )
        self.assertEqual(len(result["results"]), op.FUZZER_MAX_PAYLOADS)

    def test_fuzzer_rejects_missing_marker(self):
        result = op.zap_fuzzer_send("POST", "/search", "q=static", marker="§§", payloads=["a"])
        self.assertEqual(result["status"], "error")


class BrowseThroughZapTests(unittest.TestCase):
    def setUp(self):
        op._zap_history.clear()

    def test_blocked_path_never_reaches_requests(self):
        result = op.browse_through_zap("GET", "http://evil.com/", session_id="sess-C")
        self.assertEqual(result["status_code"], 400)
        self.assertEqual(op._zap_history, [])

    def test_successful_proxy_records_browser_source_history(self):
        class FakeResponse:
            status_code = 200
            content = b"<html>ok</html>"
            headers = {"Content-Type": "text/html"}
            raw = None

        with patch.object(op.requests, "request", return_value=FakeResponse()):
            result = op.browse_through_zap("GET", "search", session_id="sess-C", module_id="recon")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(len(op._zap_history), 1)
        self.assertEqual(op._zap_history[-1]["source"], "browser")
        self.assertEqual(op._zap_history[-1]["session_id"], "sess-C")


if __name__ == "__main__":
    unittest.main()
