import ast
import unittest
from pathlib import Path

# Was `Path(__file__).parent / "ATTENSE_app" / "blueteam"` -- stale even before
# this restructure (blueteam was never nested inside ATTENSE_app). Fixed to the
# real location: the package nested under the blue-team-api service directory
# (see apps/blue-team-api/Dockerfile for why it's nested one level deep).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BLUE_TEAM = _REPO_ROOT / "apps" / "blue-team-api" / "blueteam"
AMBIGUOUS_ROOTS = {"api", "config", "core", "infrastructure", "schemas"}


class BlueTeamPackagingTests(unittest.TestCase):
    def test_python_sources_parse(self):
        for path in BLUE_TEAM.rglob("*.py"):
            with self.subTest(path=path.relative_to(BLUE_TEAM)):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_internal_imports_are_package_relative(self):
        for path in BLUE_TEAM.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    root = node.module.split(".", 1)[0]
                    self.assertNotIn(
                        root,
                        AMBIGUOUS_ROOTS,
                        f"{path.relative_to(BLUE_TEAM)} imports ambiguous top-level package {root}",
                    )


if __name__ == "__main__":
    unittest.main()
