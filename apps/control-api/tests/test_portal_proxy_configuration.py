import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

class PortalProxyConfigurationTests(unittest.TestCase):
    def test_portal_dev_proxy_targets_local_control_api(self):
        config_path = Path(__file__).resolve().parents[3] / 'frontends' / 'portal' / 'vite.config.js'
        self.assertTrue(config_path.exists(), 'portal vite.config.js should exist')
        text = config_path.read_text(encoding='utf-8')
        self.assertIn("target: 'http://127.0.0.1:8020'", text)

        def test_control_api_cors_allows_localhost_and_127(self):
            main_path = Path(__file__).resolve().parents[1] / 'main.py'
            self.assertTrue(main_path.exists(), 'control-api main.py should exist')
            text = main_path.read_text(encoding='utf-8')
            self.assertIn('http://127.0.0.1:3000', text)
            self.assertIn('http://127.0.0.1:5173', text)

if __name__ == '__main__':
    unittest.main()
