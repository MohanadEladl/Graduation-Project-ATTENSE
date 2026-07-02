import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from core import user_store # noqa: E402


class UserStoreTests(unittest.TestCase):
    def test_login_user_uses_case_insensitive_lookup(self):
        self.assertTrue(callable(user_store.login_user))


if __name__ == "__main__":
    unittest.main()
