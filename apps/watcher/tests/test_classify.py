"""Unit coverage for the Watcher Agent's per-command Ollama classifier."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

import agent  # noqa: E402


def _ollama_response(body: dict | str) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"response": body if isinstance(body, str) else json.dumps(body)}
    return resp


class VerbRuleTests(unittest.TestCase):
    """Commands matching a known verb are classified deterministically and
    never reach Ollama -- direct testing showed the model is unreliable even
    on textbook commands like `cat` and `sha256sum` without few-shot
    examples, so the common case must not depend on it."""

    def test_known_read_verbs_are_investigation_started(self):
        for cmd in ("cat /var/log/auth.log", "less /var/log/nginx/access.log",
                    "grep -r Failed /var/log/", "ls -la /tmp", "ps aux"):
            self.assertEqual(agent._classify_by_verb(cmd), "investigation_started", cmd)

    def test_hashing_and_copy_verbs_are_evidence_preserved(self):
        for cmd in ("sha256sum /var/log/access.log", "md5sum /etc/passwd",
                    "cp /var/log/auth.log /tmp/evidence/auth.log", "tar czf ev.tar.gz /var/log"):
            self.assertEqual(agent._classify_by_verb(cmd), "evidence_preserved", cmd)

    def test_iptables_block_is_containment_initiated(self):
        self.assertEqual(
            agent._classify_by_verb("iptables -A INPUT -s 10.0.0.42 -j DROP"),
            "containment_initiated",
        )

    def test_iptables_list_is_containment_succeeded(self):
        self.assertEqual(agent._classify_by_verb("iptables -L"), "containment_succeeded")

    def test_ufw_status_is_containment_succeeded(self):
        self.assertEqual(agent._classify_by_verb("ufw status"), "containment_succeeded")

    def test_ufw_block_is_containment_initiated(self):
        self.assertEqual(agent._classify_by_verb("ufw deny from 1.2.3.4"), "containment_initiated")

    def test_systemctl_disable_is_eradication_completed(self):
        self.assertEqual(agent._classify_by_verb("systemctl disable malware.service"), "eradication_completed")

    def test_systemctl_status_is_recovery_validated(self):
        self.assertEqual(agent._classify_by_verb("systemctl status nginx"), "recovery_validated")

    def test_systemctl_stop_is_containment_initiated(self):
        self.assertEqual(agent._classify_by_verb("systemctl stop nginx"), "containment_initiated")

    def test_unknown_systemctl_subcommand_falls_back(self):
        self.assertIsNone(agent._classify_by_verb("systemctl restart nginx"))

    def test_tcpdump_with_write_flag_is_evidence_preserved(self):
        self.assertEqual(agent._classify_by_verb("tcpdump -w /tmp/capture.pcap"), "evidence_preserved")

    def test_tcpdump_without_write_flag_falls_back(self):
        self.assertIsNone(agent._classify_by_verb("tcpdump -i eth0"))

    def test_unknown_verb_falls_back_to_none(self):
        self.assertIsNone(agent._classify_by_verb("some-custom-tool --flag"))

    def test_empty_command_falls_back_to_none(self):
        self.assertIsNone(agent._classify_by_verb("   "))

    @patch("agent.requests.post")
    def test_classify_command_skips_ollama_for_known_verbs(self, mock_post):
        result = agent._classify_command("cat /var/log/auth.log")
        self.assertEqual(result, "investigation_started")
        mock_post.assert_not_called()


class ClassifyCommandTests(unittest.TestCase):
    @patch("agent.requests.post")
    def test_valid_event_type_is_returned(self, mock_post):
        mock_post.return_value = _ollama_response({"event_type": "investigation_started"})
        result = agent._classify_command("some-custom-soc-tool --inspect")
        self.assertEqual(result, "investigation_started")

    @patch("agent.requests.post")
    def test_none_classification_is_not_an_error(self, mock_post):
        mock_post.return_value = _ollama_response({"event_type": "none"})
        result = agent._classify_command("some-custom-soc-tool --noop")
        self.assertEqual(result, "none")

    @patch("agent.requests.post")
    def test_unrecognised_event_type_returns_none(self, mock_post):
        mock_post.return_value = _ollama_response({"event_type": "totally_made_up"})
        result = agent._classify_command("some-custom-soc-tool --inspect")
        self.assertIsNone(result)

    @patch("agent.requests.post")
    def test_malformed_json_returns_none(self, mock_post):
        mock_post.return_value = _ollama_response("not json at all")
        result = agent._classify_command("some-custom-soc-tool --inspect")
        self.assertIsNone(result)

    @patch("agent.requests.post")
    def test_request_exception_returns_none(self, mock_post):
        mock_post.side_effect = agent.requests.RequestException("connection refused")
        result = agent._classify_command("some-custom-soc-tool --inspect")
        self.assertIsNone(result)

    @patch("agent.requests.post")
    def test_request_uses_json_format_and_zero_temperature(self, mock_post):
        mock_post.return_value = _ollama_response({"event_type": "evidence_preserved"})
        agent._classify_command("some-custom-soc-tool --inspect")
        _, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload["format"], "json")
        self.assertEqual(payload["options"]["temperature"], 0)


class FlushOwnsOffsetAndDetailTests(unittest.TestCase):
    """_flush() must not trust the model for t_offset_sec or detail text —
    both are derived from the real (t_offset, command) tuple the tail thread
    already captured, so the model has nothing left to hallucinate."""

    @patch("agent._post_action")
    @patch("agent._classify_command")
    def test_classified_command_posts_with_owned_offset_and_detail(self, mock_classify, mock_post_action):
        mock_classify.return_value = "containment_initiated"
        agent._cmd_queue.put((42, "iptables -A INPUT -s 10.0.0.42 -j DROP"))

        agent._flush("analyst-1", "incident-1", "APP-01", session_start=1000.0)

        mock_post_action.assert_called_once()
        _, kwargs = mock_post_action.call_args
        self.assertEqual(kwargs["t_offset_sec"], 42)
        self.assertEqual(kwargs["detail"], "Analyst ran: iptables -A INPUT -s 10.0.0.42 -j DROP")
        self.assertEqual(kwargs["timestamp"], 1042.0)

    @patch("agent._write_raw_log")
    @patch("agent._post_action")
    @patch("agent._classify_command")
    def test_none_classification_is_skipped_not_logged(self, mock_classify, mock_post_action, mock_raw_log):
        mock_classify.return_value = "none"
        agent._cmd_queue.put((5, "ls -la"))

        agent._flush("analyst-1", "incident-1", "APP-01", session_start=1000.0)

        mock_post_action.assert_not_called()
        mock_raw_log.assert_not_called()

    @patch("agent._write_raw_log")
    @patch("agent._post_action")
    @patch("agent._classify_command")
    def test_failed_classification_goes_to_raw_log_not_silently_dropped(
        self, mock_classify, mock_post_action, mock_raw_log
    ):
        mock_classify.return_value = None
        agent._cmd_queue.put((7, "some weird command"))

        agent._flush("analyst-1", "incident-1", "APP-01", session_start=1000.0)

        mock_post_action.assert_not_called()
        mock_raw_log.assert_called_once_with(
            "analyst-1", "incident-1", [(7, "some weird command")], reason="ollama_classification_failed"
        )


if __name__ == "__main__":
    unittest.main()
