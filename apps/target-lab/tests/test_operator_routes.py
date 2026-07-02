"""Characterization tests for guided vs operator-mode target routes."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

try:
    from flask import Flask
except ModuleNotFoundError as exc:
    raise unittest.SkipTest('Flask is required for target-lab route tests') from exc

APP_DIR = Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import evidence # noqa: E402
from routes.auth import auth_bp # noqa: E402
from routes.home import home_bp # noqa: E402
from routes.profile import _PROFILES, profile_bp # noqa: E402
from routes.search import search_bp # noqa: E402
from routes_op.auth import auth_op_bp # noqa: E402
from routes_op.home import home_op_bp # noqa: E402
from routes_op.profile import profile_op_bp # noqa: E402
from routes_op.search import search_op_bp # noqa: E402
from routes_op.system import _sanitize_host # noqa: E402


class OperatorRouteModeTests(unittest.TestCase):
    def setUp(self):
        evidence.reset()
        _PROFILES["guest"]["email"] = "guest@lab.local"
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.app.lab_url = lambda path: path
        self.app.detect_via = lambda: "attackbox"

        @self.app.context_processor
        def _inject_lab_url():
            return {"lab_url": self.app.lab_url}

            self.app.register_blueprint(home_bp)
            self.app.register_blueprint(auth_bp, url_prefix="/auth")
            self.app.register_blueprint(search_bp)
            self.app.register_blueprint(profile_bp, url_prefix="/profile")
            self.app.register_blueprint(home_op_bp, url_prefix="/op")
            self.app.register_blueprint(auth_op_bp, url_prefix="/op/auth")
            self.app.register_blueprint(search_op_bp, url_prefix="/op")
            self.app.register_blueprint(profile_op_bp, url_prefix="/op/profile")
            self.client = self.app.test_client()

            def test_guided_login_enumerates_user_but_operator_login_does_not(self):
                guided = self.client.post("/auth/login", data={"username": "admin", "password": "wrong"})
                operator = self.client.post("/op/auth/login", data={"username": "admin", "password": "wrong"})

                self.assertEqual(guided.status_code, 401)
                self.assertIn(b"Incorrect password for <strong>admin</strong>", guided.data)
                self.assertEqual(operator.status_code, 401)
                self.assertIn(b"Invalid credentials", operator.data)
                self.assertNotIn(b"Incorrect password", operator.data)

                def test_operator_search_blocks_script_tag_but_keeps_event_handler_bypass(self):
                    script_payload = "<script>alert(1)</script>"
                    handler_payload = '<img src=x onerror="alert(1)">'

                    guided = self.client.get("/search", query_string={"q": script_payload})
                    operator_script = self.client.get("/op/search", query_string={"q": script_payload})
                    operator_handler = self.client.get("/op/search", query_string={"q": handler_payload})

                    self.assertIn(script_payload.encode(), guided.data)
                    self.assertNotIn(b"<script>", operator_script.data.lower())
                    self.assertIn(b"onerror", operator_handler.data.lower())

                    def test_operator_command_sanitizer_filters_obvious_separators_only(self):
                        self.assertEqual(_sanitize_host("127.0.0.1; id | whoami"), "127.0.0.1 id whoami")
                        self.assertIn("`id`", _sanitize_host("127.0.0.1 `id`"))
                        self.assertIn("$(id)", _sanitize_host("127.0.0.1 $(id)"))

                        def test_operator_recon_moves_easy_clues_to_git_config(self):
                            guided = self.client.get("/robots.txt")
                            operator_robots = self.client.get("/op/robots.txt")
                            operator_git = self.client.get("/op/.git/config")

                            self.assertEqual(guided.status_code, 200)
                            self.assertIn(b"Disallow: /admin/", guided.data)
                            self.assertEqual(operator_robots.status_code, 404)
                            self.assertEqual(operator_git.status_code, 200)
                            self.assertIn(b"staff-portal.git", operator_git.data)

                            def test_guided_profile_update_accepts_missing_csrf_but_operator_rejects_bad_referer(self):
                                guided = self.client.post("/profile/update", data={"email": "changed@lab.local"})
                                operator = self.client.post("/op/profile/update", data={"email": "blocked@lab.local"})

                                self.assertEqual(guided.status_code, 200)
                                self.assertIn(b"Email updated successfully", guided.data)
                                self.assertEqual(operator.status_code, 403)
                                self.assertIn(b"CSRF check failed", operator.data)


if __name__ == "__main__":
    unittest.main()