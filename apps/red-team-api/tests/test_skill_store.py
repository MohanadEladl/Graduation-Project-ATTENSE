"""Unit coverage for learner progress persistence."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from backend import skill_store # noqa: E402


class SkillStoreTests(unittest.TestCase):
    def test_update_keeps_the_best_score_and_records_attempts(self):
        temp_dir = Path(__file__).resolve().parents[3] / ".tmp" / "pytest"
        temp_dir.mkdir(parents=True, exist_ok=True)
        path = temp_dir / f"red-team-skill-store-test-{os.getpid()}.json"
        try:
            with patch.object(skill_store, "_SKILLS_PATH", str(path)):
                data = skill_store.update("xss", "basic", 70, "B")
                data = skill_store.update("xss", "basic", 60, "C")
            entry = data["xss"]["basic"]
            self.assertEqual(entry["attempts"], 2)
            self.assertEqual(entry["best_score"], 70)
            self.assertEqual(entry["technique_scores"], [70, 60])
        finally:
            try:
                path.unlink(missing_ok=True)
            except PermissionError:
                pass
