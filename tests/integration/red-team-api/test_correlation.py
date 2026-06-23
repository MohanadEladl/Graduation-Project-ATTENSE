"""Phase 4 correlation tests for the red-team producer.

Proves the TTD-anchor fix: the malicious_action_executed event carries the
attack START time (AttackResult.started_at), not the completion time, and the
event_sink payload is the canonical contract shape (source/run_id/source_event_id).

    # from repo root (discover, not dotted import -- "red-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/red-team-api -p test_correlation.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/red-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_RED_TEAM_DIR = os.path.join(_REPO, "apps", "red-team-api")
if _RED_TEAM_DIR not in sys.path:
    sys.path.insert(0, _RED_TEAM_DIR)

from core import event_sink
from core.engine import Engine
from core.models import AttackResult, TargetConfig


class _StubLog:
    def info(self, *a, **k):
        pass

    warning = error = log_result = info


class _StubModule:
    module_id = "xss-01"
    name = "XSS"
    scenario_id = "APP-01"

    def __init__(self, result):
        self._result = result

    def validate(self, opts, target):
        return None

    def execute(self, target, opts, log_fn):
        return self._result


class EventSinkPayloadTests(unittest.TestCase):
    def test_payload_is_canonical_contract_shape(self):
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["json"] = json

            class _Resp:
                def raise_for_status(self):
                    pass

            return _Resp()

        original = event_sink.requests.post
        event_sink.requests.post = fake_post
        try:
            event_sink.post_malicious_action_event(
                event_id="run-1",
                incident_id="INC-1",
                scenario_id="APP-01",
                actor_id="op",
                target_id="http://target",
                outcome="success",
                timestamp="2026-01-01T10:00:00+00:00",
                metadata={},
                run_id="run-5",
            )
        finally:
            event_sink.requests.post = original

        payload = captured["json"]
        self.assertEqual(payload["source"], "red-team")
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["run_id"], "run-5")
        self.assertIn("source_event_id", payload)
        self.assertEqual(payload["event_type"], "malicious_action_executed")
        self.assertEqual(payload["timestamp"], "2026-01-01T10:00:00+00:00")


class EngineTtdAnchorTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("INCIDENT_ID", None)

    def test_event_uses_attack_start_time_not_completion(self):
        os.environ["INCIDENT_ID"] = "INC-1"
        result = AttackResult(
            module_id="xss-01",
            module_name="XSS",
            scenario_id="APP-01",
            target="http://target",
            started_at="2026-01-01T10:00:00+00:00",
            finished_at="2026-01-01T10:05:00+00:00",  # 5 min later
            total_steps=1,
            successful_steps=1,
        )
        engine = Engine({"xss-01": _StubModule(result)}, _StubLog())

        captured = {}

        def fake_emit(**kwargs):
            captured.update(kwargs)

        original = event_sink.post_malicious_action_event
        event_sink.post_malicious_action_event = fake_emit
        try:
            engine.run_module("xss-01", TargetConfig())
        finally:
            event_sink.post_malicious_action_event = original

        # The TTD anchor is the attack start, not the 5-minutes-later completion.
        self.assertEqual(captured["timestamp"], "2026-01-01T10:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
