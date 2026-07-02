"""Unit tests for shared target-lab route security helpers."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from route_security import ( # noqa: E402
GUIDED_DANGEROUS_UPLOAD_EXTENSIONS,
OPERATOR_BLOCKED_UPLOAD_EXTENSIONS,
OPERATOR_DANGEROUS_BUT_ACCEPTED_EXTENSIONS,
has_command_output_indicator,
has_effective_xss_payload,
has_extension,
has_sensitive_file_content,
has_shell_separator,
has_traversal_pattern,
has_xss_payload,
)


class RouteSecurityHelperTests(unittest.TestCase):
    def test_xss_payload_detection_distinguishes_script_from_bypass(self):
        self.assertTrue(has_xss_payload("<script>alert(1)</script>"))
        self.assertTrue(has_xss_payload('<img src=x onerror="alert(1)">'))
        self.assertFalse(has_effective_xss_payload("<script>alert(1)</script>"))
        self.assertTrue(has_effective_xss_payload('<img src=x onerror="alert(1)">'))

        def test_shell_separator_detection_matches_guided_and_operator_modes(self):
            self.assertTrue(has_shell_separator("127.0.0.1; id"))
            self.assertTrue(has_shell_separator("127.0.0.1 $(id)"))
            self.assertFalse(has_shell_separator("127.0.0.1"))

            def test_output_and_file_disclosure_indicators(self):
                self.assertTrue(has_command_output_indicator("uid=0(root) gid=0(root)"))
                self.assertTrue(has_sensitive_file_content("root:x:0:0:root:/root:/bin/bash"))
                self.assertFalse(has_command_output_indicator("2 packets transmitted"))

                def test_traversal_detection_covers_encoded_and_absolute_paths(self):
                    self.assertTrue(has_traversal_pattern("../../etc/passwd"))
                    self.assertTrue(has_traversal_pattern("%2e%2e/%2e%2e/etc/passwd"))
                    self.assertTrue(has_traversal_pattern("/etc/passwd"))
                    self.assertFalse(has_traversal_pattern("readme.txt"))

                    def test_upload_extension_sets_preserve_mode_differences(self):
                        self.assertTrue(has_extension("shell.php", GUIDED_DANGEROUS_UPLOAD_EXTENSIONS))
                        self.assertTrue(has_extension("shell.php", OPERATOR_BLOCKED_UPLOAD_EXTENSIONS))
                        self.assertFalse(has_extension("shell.phtml", OPERATOR_BLOCKED_UPLOAD_EXTENSIONS))
                        self.assertTrue(has_extension("shell.phtml", OPERATOR_DANGEROUS_BUT_ACCEPTED_EXTENSIONS))


if __name__ == "__main__":
    unittest.main()