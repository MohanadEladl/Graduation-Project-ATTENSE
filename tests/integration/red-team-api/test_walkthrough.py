"""Regression tests for the guided-room walkthrough content.

The restructuring that moved red-team from the old top-level `red-team/`
directory into `apps/red-team-api` silently dropped `lab_progress.py`'s
WALKTHROUGH/SECTION_TECHNIQUES/REFERENCES teaching content and the
`GET /api/modules/{module_id}/walkthrough` route - the frontend
(Workspace.jsx) still called it and quietly degraded to a generic
client-built walkthrough (`buildFallbackWalkthrough`) whenever the response
had no `sections`, which was always. These tests pin the restored content and
route so this can't silently regress again.

    # from repo root (discover, not dotted import -- "red-team-api" has a
    # hyphen and isn't a valid Python module path segment)
    py -m unittest discover -s tests/integration/red-team-api -p test_walkthrough.py
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))  # tests/integration/red-team-api
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_RED_TEAM_DIR = os.path.join(_REPO, "apps", "red-team-api")
if _RED_TEAM_DIR not in sys.path:
    sys.path.insert(0, _RED_TEAM_DIR)

from backend import lab_progress  # noqa: E402


class BuildWalkthroughContentTests(unittest.TestCase):
    def test_every_module_variant_has_real_teaching_content(self):
        # Every (module_id, variant_id) MODULE_VARIANTS advertises must have a
        # matching WALKTHROUGH entry - if any drift apart, the frontend's
        # `r?.sections?.length` check falls back to the generic walkthrough
        # for that variant.
        for module_id, variants in lab_progress.MODULE_VARIANTS.items():
            for variant_id in variants:
                with self.subTest(module_id=module_id, variant_id=variant_id):
                    out = lab_progress.build_walkthrough(module_id, variant_id)
                    self.assertTrue(out["sections"], f"{module_id}/{variant_id} has no sections")
                    self.assertTrue(out["overview"], f"{module_id}/{variant_id} has no overview")
                    for section in out["sections"]:
                        self.assertTrue(section["mitre"], f"{module_id}/{variant_id} section missing MITRE mapping")
                        self.assertTrue(section["what"])
                        self.assertTrue(section["how"])

    def test_reference_and_database_refs_present_for_every_module(self):
        for module_id in lab_progress.MODULE_VARIANTS:
            with self.subTest(module_id=module_id):
                out = lab_progress.build_walkthrough(module_id)
                self.assertIsNotNone(out["reference"])
                self.assertIn("url", out["reference"])
                self.assertTrue(out["database_refs"])

    def test_no_variant_id_defaults_to_first_variant(self):
        out = lab_progress.build_walkthrough("recon", None)
        self.assertEqual(out["variant_id"], next(iter(lab_progress.MODULE_VARIANTS["recon"])))

    def test_unknown_module_degrades_safely_without_raising(self):
        out = lab_progress.build_walkthrough("no_such_module", None)
        self.assertEqual(out["sections"], [])
        self.assertIsNone(out["overview"])
        self.assertIsNone(out["reference"])

    def test_get_walkthrough_defaults_to_first_variant(self):
        wt = lab_progress.get_walkthrough("csrf", None)
        self.assertIsNotNone(wt)
        self.assertIn("overview", wt)

    def test_get_walkthrough_unknown_module_is_none(self):
        self.assertIsNone(lab_progress.get_walkthrough("no_such_module", None))


class WalkthroughRouteTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from backend.main import app

        self.client = TestClient(app)

    def test_route_returns_real_sections_not_empty(self):
        r = self.client.get("/api/modules/brute_force/walkthrough")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["sections"])
        self.assertEqual(body["variant_id"], "password_spray")

    def test_route_honors_explicit_variant_id(self):
        r = self.client.get("/api/modules/xss/walkthrough?variant_id=stored_attempt")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["variant_id"], "stored_attempt")

    def test_route_unknown_module_is_a_safe_empty_payload_not_an_error(self):
        r = self.client.get("/api/modules/no_such_module/walkthrough")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sections"], [])


if __name__ == "__main__":
    unittest.main()
