import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from core import user_store # noqa: E402


class PortalBlueTeamFlowTests(unittest.TestCase):
    def test_login_lookup_matches_portal_identifier_before_password_check(self):
        mock_row = {
        'user_id': 1,
        'username': 'user@example.com',
        'email': 'user@example.com',
        'hashed_password': '$2b$12$dummyhashplaceholder',
        'role': 'soc_l1',
        'company_id': 1,
        'user_type': None,
        'hive_key': None,
        'active_room_id': None,
        }
        class Cursor:
            def execute(self, *args, **kwargs):
                return None

                def fetchone(self):
                    return mock_row

                    def __enter__(self):
                        return self

                        def __exit__(self, exc_type, exc, tb):
                            return False

                            class Conn:
                                def __init__(self):
                                    self._cursor = Cursor()

                                    def cursor(self):
                                        return self._cursor

                                        def __enter__(self):
                                            return self

                                            def __exit__(self, exc_type, exc, tb):
                                                return False

                                                conn = Conn()

                                                with patch.object(user_store, 'connection', return_value=conn), \
                                                patch.object(user_store.bcrypt, 'checkpw', return_value=False):
                                                    user = user_store.login_user('User@Example.com', 'secret123')

                                                    self.assertIsNone(user)

                                                    def test_blue_team_app_portal_room_context_is_parsed(self):
                                                        app_path = Path(__file__).resolve().parents[3] / 'frontends' / 'blue-team' / 'src' / 'App.jsx'
                                                        self.assertTrue(app_path.exists(), 'Blue Team app source should exist')
                                                        self.assertIn('portalRoom', app_path.read_text(encoding='utf-8'))
                                                        self.assertIn('captureTokenFromUrl', app_path.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
