import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from core import user_store # noqa: E402


class PortalBlueTeamSmokeTests(unittest.TestCase):
    def test_login_lookup_and_portal_redirect_logic_are_present(self):
        user_store_path = Path(__file__).resolve().parents[1] / 'core' / 'user_store.py'
        login_page_path = Path(__file__).resolve().parents[3] / 'frontends' / 'portal' / 'blue-login.html'
        blue_app_path = Path(__file__).resolve().parents[3] / 'frontends' / 'blue-team' / 'src' / 'App.jsx'
        portal_page_path = Path(__file__).resolve().parents[3] / 'frontends' / 'portal' / 'blue-report.html'

        self.assertTrue(user_store_path.exists(), 'auth store file should exist')
        self.assertTrue(login_page_path.exists(), 'portal login page should exist')
        self.assertTrue(blue_app_path.exists(), 'Blue Team app source should exist')
        self.assertTrue(portal_page_path.exists(), 'portal room page should exist')

        user_store_text = user_store_path.read_text(encoding='utf-8')
        login_page_text = login_page_path.read_text(encoding='utf-8')
        blue_app_text = blue_app_path.read_text(encoding='utf-8')
        portal_page_text = portal_page_path.read_text(encoding='utf-8')

        self.assertIn('lower(u.username)', user_store_text)
        self.assertIn('http://127.0.0.1:3100/', login_page_text)
        self.assertIn('portalRoom', blue_app_text)
        self.assertIn('attense_session_token', portal_page_text)


if __name__ == '__main__':
    unittest.main()
