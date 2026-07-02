"""Print a conservative folder-structure redundancy audit.

This script is read-only. It groups repeated directory names and prints local
artifact candidates that should be ignored or reviewed before cleanup.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IGNORE_DIR_NAMES = {
".git",
".venv",
".pytest_cache",
".ruff_cache",
".npm-cache",
"__pycache__",
"node_modules",
"dist",
}
IGNORE_ROOTS = {
ROOT / "uploads",
ROOT / "test_logs",
}
PROJECT_ROOTS = [
ROOT / "apps",
ROOT / "frontends",
ROOT / "packages",
ROOT / "tests",
ROOT / "scripts",
ROOT / "infra",
ROOT / "integrations",
]
LOCAL_CANDIDATES = [
ROOT / ".thumbnail",
ROOT / "dashboard.dc.html",
ROOT / "report.dc.html",
ROOT / "rooms.dc.html",
ROOT / "support.js",
ROOT / "test_full_cycle.py",
ROOT / "assets",
ROOT / "uploads",
ROOT / "test_logs",
ROOT / "frontends" / "red-team" / "_shot.mjs",
ROOT / "frontends" / "red-team" / "_home_shot.png",
ROOT / "frontends" / "red-team" / "_g1_shot.png",
]


def should_skip(path: Path) -> bool:
    if path.name in IGNORE_DIR_NAMES:
        return True
        return any(path == root or root in path.parents for root in IGNORE_ROOTS)


def walk_dirs(root: Path):
    if not root.exists():
        return
        stack = [root]
        while stack:
            current = stack.pop()
            if should_skip(current):
                continue
            yield current
            try:
                children = [p for p in current.iterdir() if p.is_dir()]
            except OSError:
                continue
            stack.extend(children)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> None:
    groups: dict[str, list[Path]] = defaultdict(list)
    for root in PROJECT_ROOTS:
        for directory in walk_dirs(root):
            groups[directory.name].append(directory)

            print("# Folder Structure Redundancy Audit")
            print()
            print("## Repeated Directory Names")
            print()
            for name, paths in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0].lower())):
                if len(paths) < 2:
                    continue
                    print(f"### {name} ({len(paths)})")
                    for path in sorted(paths, key=rel):
                        print(f"- `{rel(path)}`")
                        print()

                        print("## Local / Generated Artifact Candidates")
                        print()
                        for path in LOCAL_CANDIDATES:
                            if path.exists():
                                kind = "dir" if path.is_dir() else "file"
                                print(f"- `{rel(path)}` ({kind})")


if __name__ == "__main__":
    main()
