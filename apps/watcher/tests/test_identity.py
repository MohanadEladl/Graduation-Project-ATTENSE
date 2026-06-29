"""Unit coverage for Watcher analyst identity normalization."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from identity import _extract_name, _slugify  # noqa: E402


class IdentityTests(unittest.TestCase):
    def test_slugify_normalizes_human_names(self):
        self.assertEqual(_slugify("  Alice A. Smith  "), "alice-a-smith")

    def test_slugify_uses_safe_default_for_blank_name(self):
        self.assertEqual(_slugify("---"), "analyst")

    def test_extract_name_removes_only_the_identity_prefix(self):
        self.assertEqual(_extract_name("analyst-alice-smith"), "alice-smith")
