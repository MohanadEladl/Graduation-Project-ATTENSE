"""Unit coverage for local MITRE ATT&CK keyword matching."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from app.mitre_attack import get_technique_summary, match_techniques  # noqa: E402


class MitreAttackTests(unittest.TestCase):
    def test_keyword_match_preserves_the_mitre_identifier(self):
        matches = match_techniques("nmap -sV found open ports")
        self.assertTrue(any(match["technique_id"] == "T1595" for match in matches))

    def test_summary_contains_known_technique(self):
        self.assertIn("T1190", get_technique_summary())
