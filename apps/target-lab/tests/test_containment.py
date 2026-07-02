"""Unit coverage for safe runtime-containment state changes."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
WORKSPACE_TMP = REPO_ROOT / ".tmp" / "pytest"
WORKSPACE_TMP.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(APP_ROOT))

from app import containment # noqa: E402


class ContainmentTests(unittest.TestCase):
    def test_enable_persists_sanitize_input(self):
        state_path = WORKSPACE_TMP / "containment-state-test.json"
        state_path.unlink(missing_ok=True)
        with patch.object(containment, "STATE_PATH", state_path):
                containment.enable("sanitize_input")
                self.assertTrue(containment.is_enabled("sanitize_input"))
                state_path.unlink(missing_ok=True)

    def test_block_path_requires_a_value(self):
        with self.assertRaises(ValueError):
            containment.enable("block_path")