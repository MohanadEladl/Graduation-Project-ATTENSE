"""Tests for the MITRE ATT&CK keyword scanner."""

import sys
import os

_zd_root = os.path.join(os.path.dirname(__file__), "..", "..", "apps", "zeroday-agent")
sys.path.insert(0, os.path.normpath(_zd_root))
for key in [k for k in sys.modules if k == "app" or k.startswith("app.")]:
    del sys.modules[key]

from app.mitre_attack import match_techniques, get_technique_summary


def test_match_techniques_nmap():
    matches = match_techniques("Running nmap -sV 192.168.1.1")
    technique_ids = [m["technique_id"] for m in matches]
    assert "T1595" in technique_ids


def test_match_techniques_brute_force():
    matches = match_techniques("hydra brute force attempt failed")
    technique_ids = [m["technique_id"] for m in matches]
    assert "T1110" in technique_ids


def test_match_techniques_no_match():
    matches = match_techniques("Container started successfully, health check passed")
    assert matches == []


def test_match_techniques_multiple():
    log = "nmap scan detected\nhydra brute force\n/etc/shadow accessed"
    matches = match_techniques(log)
    technique_ids = {m["technique_id"] for m in matches}
    assert "T1595" in technique_ids
    assert "T1110" in technique_ids
    assert "T1003" in technique_ids


def test_get_technique_summary_not_empty():
    summary = get_technique_summary()
    assert len(summary) > 100
    assert "T1595" in summary
    assert "Reconnaissance" in summary


def test_match_returns_expected_fields():
    matches = match_techniques("nmap port scan")
    assert len(matches) > 0
    m = matches[0]
    assert "technique_id" in m
    assert "technique_name" in m
    assert "tactic" in m
    assert "matched_keywords" in m
    assert "url" in m
