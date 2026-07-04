"""
Frontend wiring static checks — assert the ZAP workspace / brute-force pipeline
is wired correctly in source, without needing a browser or node runtime.

Covers frontend items A–J from the test plan. These read the committed frontend
source and assert the presence/order of the load-bearing wiring.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
FE = ROOT / "red-team" / "frontend"


def read(rel: str) -> str:
    return (FE / rel).read_text(encoding="utf-8")


# A. /target-zap must come BEFORE /target in the Vite proxy (prefix matching).
def test_vite_target_zap_before_target():
    cfg = read("vite.config.js")
    # Match the proxy KEY definitions ("'/target-zap':" / "'/target':"), not the
    # substring inside comments, so ordering is asserted on the real keys.
    i_zap = cfg.find("'/target-zap':")
    i_target = cfg.find("'/target':")
    assert i_zap != -1, "vite proxy missing /target-zap key"
    assert i_target != -1, "vite proxy missing /target key"
    assert i_zap < i_target, "/target-zap proxy key must be declared before /target"
    assert "/zap-browse" in cfg


# B. nginx forwards /target-zap/ to the backend /zap-browse/.
def test_nginx_target_zap_route():
    conf = read("nginx.conf")
    assert "location /target-zap/" in conf
    assert re.search(r"/target-zap/\(\.\*\)\$\s*/zap-browse/\$1", conf), "rewrite to /zap-browse missing"


# C. ZAP Workspace route exists in App.jsx.
def test_app_has_zap_workspace_route():
    app = read("src/App.jsx")
    assert "ZapWorkspace" in app
    assert 'path="/zap-workspace"' in app


# D. The launcher opens the ZAP workspace with session_id, module_id, mode.
def test_launcher_opens_workspace_with_context():
    js = read("src/components/zap/ZapLauncher.jsx")
    assert "window.open" in js
    assert "/zap-workspace" in js
    for key in ("session_id", "module_id", "mode"):
        assert key in js, f"launcher missing {key}"


# E/F. api client forwards session/module (context) and fuzzer forwards headers.
def test_api_client_forwards_context_and_headers():
    client = read("src/api/client.js")
    rep = next(l for l in client.splitlines() if "repeater:" in l or "repeater/send" in l)
    assert "...context" in client
    # fuzzer must forward headers AND context
    fuzz_block = client[client.find("fuzzer:"):client.find("fuzzer:") + 300]
    assert "headers" in fuzz_block, "fuzzer must forward headers"
    assert "...context" in fuzz_block, "fuzzer must forward session/module context"
    # attackbox exec forwards module_id + session_id
    assert re.search(r"exec:\s*\(command,\s*module_id,\s*session_id\)", client)


# controller builds context = {session_id, module_id}
def test_controller_context_and_sends():
    ctrl = read("src/components/zap/useZapController.js")
    assert re.search(r"context\s*=\s*\{\s*session_id[^}]*module_id", ctrl)
    # H. sendToRepeater preserves method/path/headers/body
    send_rep = ctrl[ctrl.find("sendToRepeater"):ctrl.find("sendToRepeater") + 400]
    for setter in ("setRepMethod", "setRepPath", "setRepHeaders", "setRepBody"):
        assert setter in send_rep, f"sendToRepeater must set {setter}"
    # I. sendToFuzzer preserves body + inserts marker
    send_fuz = ctrl[ctrl.find("sendToFuzzer"):ctrl.find("sendToFuzzer") + 400]
    assert "insertFuzzMarker" in send_fuz
    assert "setFuzBody" in send_fuz


# G. ZapHistory exposes Inspect / Repeater / Fuzzer actions.
def test_history_has_three_actions():
    hist = read("src/components/zap/ZapHistory.jsx")
    for action in ("Inspect", "Repeater", "Fuzzer"):
        assert action in hist, f"history row missing {action} action"
    for handler in ("onInspect", "onRepeater", "onFuzzer"):
        assert handler in hist


# I(cont). insertFuzzMarker actually inserts the § marker.
def test_fuzz_marker_helper_inserts_section_sign():
    utils = read("src/components/zap/zapUtils.js")
    assert "insertFuzzMarker" in utils
    assert "§" in utils
    assert "password=" in utils  # prefers marking the password value


# J. Operator hints exist, differ from guided, and never reveal the credential.
def test_operator_hints_separate_and_no_credential_leak():
    briefings = read("src/data/missionBriefings.js")
    assert "operatorHints" in briefings, "brute_force needs operatorHints"
    # Extract the operatorHints array text.
    start = briefings.find("operatorHints")
    block = briefings[start:start + 1400]
    end = block.find("]")
    hints_text = block[:end].lower()
    # Must not leak the guided planted credential or the operator seed password.
    for secret in ("password123", "br3akme", "admin:password", "tr0ub4dor", "s3rvice@cct"):
        assert secret not in hints_text, f"operator hint leaks credential: {secret}"
    # Operator hints should be ZAP-workflow oriented.
    assert "repeater" in hints_text or "fuzzer" in hints_text or "proxy history" in hints_text


# J(all). Every module now carries operator-mode hints (parity with brute_force),
# they are ZAP/AttackBox-workflow oriented, and none leaks a solution / credential.
def test_all_modules_have_safe_operator_hints():
    briefings = read("src/data/missionBriefings.js")
    occurrences = [m.start() for m in re.finditer(r"operatorHints:\s*\[", briefings)]
    # recon, brute_force, xss, cmd_injection, dir_traversal, file_upload, csrf.
    assert len(occurrences) >= 7, f"expected 7 modules with operatorHints, found {len(occurrences)}"

    forbidden = (
        "password123", "br3akme", "admin:password", "tr0ub4dor", "s3rvice@cct",
        "guest:guest", "root:x:0:0", "../../etc/passwd", "<script>alert",
    )
    for start in occurrences:
        block = briefings[start:briefings.find("]", start)]
        low = block.lower()
        # Each operator-hint block must steer toward the approved local tools.
        assert any(k in low for k in ("repeater", "fuzzer", "proxy history", "attackbox", "ffuf", "gobuster")), \
            "operator hints must reference an approved local tool / workflow"
        # And must never hand over a working solution or credential.
        for secret in forbidden:
            assert secret.lower() not in low, f"operator hint leaks a solution: {secret}"
