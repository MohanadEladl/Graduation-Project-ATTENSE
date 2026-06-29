"""Unit coverage for safe runtime-containment state changes."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from app import containment  # noqa: E402


class ContainmentTests(unittest.TestCase):
    def test_enable_persists_sanitize_input(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(containment, "STATE_PATH", Path(temp) / "state.json"):
                containment.enable("sanitize_input")
                self.assertTrue(containment.is_enabled("sanitize_input"))

    def test_block_path_requires_a_value(self):
        with self.assertRaises(ValueError):
            containment.enable("block_path")
