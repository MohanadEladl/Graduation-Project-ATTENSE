"""Frontend wiring static checks - assert the ZAP workspace is wired correctly
in source, without needing a browser or node runtime.

Ported (with paths adapted to this repo's frontends/red-team layout, not the
old top-level red-team/frontend/ layout) from the feature/attacker-activity-log
branch's test_frontend_wiring.py. That branch's file also asserted
`operatorHints` content in missionBriefings.js and a stricter detect_via()
channel classification (zap_repeater/zap_fuzzer as distinct target-agent-level
via values) - both reflect a different, older architecture than this repo's
current design (operator/guided is distinguished by session_id/backend at the
red-team-api evidence layer, not by target-agent's own detect_via()) and are
intentionally not ported here.

    # from repo root (discover, not dotted import -- "red-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/red-team-api -p test_zap_frontend_wiring.py
"""

import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/red-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_FE = os.path.join(_REPO, "frontends", "red-team")


def _read(rel: str) -> str:
    with open(os.path.join(_FE, rel), encoding="utf-8") as f:
        return f.read()


class ZapFrontendWiringTests(unittest.TestCase):
    def test_vite_target_zap_before_target(self):
        # /target-zap must come BEFORE /target in the Vite proxy (prefix matching).
        cfg = _read("vite.config.js")
        i_zap = cfg.find("'/target-zap':")
        i_target = cfg.find("'/target':")
        self.assertNotEqual(i_zap, -1, "vite proxy missing /target-zap key")
        self.assertNotEqual(i_target, -1, "vite proxy missing /target key")
        self.assertLess(i_zap, i_target, "/target-zap proxy key must be declared before /target")

    def test_nginx_target_zap_route(self):
        conf = _read("nginx.conf")
        self.assertIn("location /target-zap/", conf)
        self.assertRegex(conf, r"\^/target-zap/\(\.\*\)\$\s*/zap-browse/\$1")

    def test_app_has_zap_workspace_route(self):
        app = _read("src/App.jsx")
        self.assertIn("ZapWorkspace", app)
        self.assertIn('path="/zap-workspace"', app)

    def test_launcher_opens_workspace_with_context(self):
        js = _read("src/components/zap/ZapLauncher.jsx")
        self.assertIn("window.open", js)
        self.assertIn("/zap-workspace", js)
        for key in ("session_id", "module_id", "mode"):
            self.assertIn(key, js, f"launcher missing {key}")

    def test_api_client_forwards_context_and_headers(self):
        client = _read("src/api/client.js")
        rep_idx = client.find("repeater:")
        rep_block = client[rep_idx:rep_idx + 300]
        self.assertIn("context.module_id", rep_block)
        self.assertIn("context.session_id", rep_block)
        fuzz_idx = client.find("fuzzer:")
        fuzz_block = client[fuzz_idx:fuzz_idx + 300]
        self.assertIn("headers", fuzz_block, "fuzzer must forward headers")
        self.assertIn("context.module_id", fuzz_block, "fuzzer must forward session/module context")

    def test_controller_context_and_sends(self):
        ctrl = _read("src/components/zap/useZapController.js")
        self.assertRegex(ctrl, r"context\s*=\s*\{\s*session_id[^}]*module_id")
        send_rep_idx = ctrl.find("sendToRepeater")
        send_rep = ctrl[send_rep_idx:send_rep_idx + 400]
        for setter in ("setRepMethod", "setRepPath", "setRepHeaders", "setRepBody"):
            self.assertIn(setter, send_rep, f"sendToRepeater must set {setter}")
        send_fuz_idx = ctrl.find("sendToFuzzer")
        send_fuz = ctrl[send_fuz_idx:send_fuz_idx + 400]
        self.assertIn("insertFuzzMarker", send_fuz)
        self.assertIn("setFuzBody", send_fuz)

    def test_history_has_three_actions(self):
        hist = _read("src/components/zap/ZapHistory.jsx")
        for action in ("Inspect", "Repeater", "Fuzzer"):
            self.assertIn(action, hist, f"history row missing {action} action")
        for handler in ("onInspect", "onRepeater", "onFuzzer"):
            self.assertIn(handler, hist)

    def test_fuzz_marker_helper_inserts_section_sign(self):
        utils = _read("src/components/zap/zapUtils.js")
        self.assertIn("insertFuzzMarker", utils)
        self.assertIn("§", utils)
        self.assertIn("password=", utils)  # prefers marking the password value


if __name__ == "__main__":
    unittest.main()
