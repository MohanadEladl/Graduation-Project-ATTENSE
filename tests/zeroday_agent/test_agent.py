"""Tests for the zero-day agent core functions."""

import importlib
import sys
import os

_zd_root = os.path.join(os.path.dirname(__file__), "..", "..", "apps", "zeroday-agent")
sys.path.insert(0, os.path.normpath(_zd_root))
for key in [k for k in sys.modules if k == "app" or k.startswith("app.")]:
    del sys.modules[key]

from app.agent import (
    _empty_analysis,
    _truncate_at_line,
    _parse_json_response,
    pre_analyze_mitre,
    generate_report,
    send_alert,
)

from tests.zeroday_agent.conftest import DEMO_LOGS, DEMO_OFFLINE_ANALYSIS


def test_empty_analysis_defaults():
    result = _empty_analysis()
    assert result["zero_day_detected"] is False
    assert result["confidence"] == "LOW"
    assert result["closest_mitre_technique"]["id"] == "UNKNOWN"


def test_empty_analysis_overrides():
    result = _empty_analysis(confidence="HIGH", severity="CRITICAL")
    assert result["confidence"] == "HIGH"
    assert result["severity"] == "CRITICAL"
    assert result["zero_day_detected"] is False


def test_truncate_at_line_short():
    text = "line1\nline2\nline3"
    assert _truncate_at_line(text, 1000) == text


def test_truncate_at_line_cuts():
    text = "line1\nline2\nline3\nline4"
    result = _truncate_at_line(text, 12)
    assert result == "line1\nline2"


def test_parse_json_response_clean():
    text = '{"zero_day_detected": true, "confidence": "HIGH"}'
    result = _parse_json_response(text)
    assert result["zero_day_detected"] is True
    assert result["confidence"] == "HIGH"


def test_parse_json_response_with_fences():
    text = '```json\n{"key": "value"}\n```'
    result = _parse_json_response(text)
    assert result["key"] == "value"


def test_parse_json_response_invalid():
    result = _parse_json_response("not json at all")
    assert result is None


def test_pre_analyze_mitre_demo_logs():
    matches = pre_analyze_mitre(DEMO_LOGS)
    assert len(matches) > 0
    assert "red-team-backend" in matches
    red_ids = [m["technique_id"] for m in matches["red-team-backend"]]
    assert "T1595" in red_ids


def test_generate_report(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.agent.os.path.dirname",
        lambda p: str(tmp_path),
    )
    mitre_matches = pre_analyze_mitre(DEMO_LOGS)
    path = generate_report(DEMO_OFFLINE_ANALYSIS, DEMO_LOGS, mitre_matches)
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "ZERO-DAY VARIANT" in content
    assert "T1190" in content
    assert "MITRE ATT&CK" in content


def test_send_alert_zero_day(capsys):
    send_alert(DEMO_OFFLINE_ANALYSIS)


def test_send_alert_normal(capsys):
    send_alert(_empty_analysis())
