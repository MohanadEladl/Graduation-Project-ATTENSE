"""Shared helpers for the TheHive/Cortex/Wazuh bootstrap scripts in this directory."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable


def wait_until_ready(
    check_fn: Callable[[], None],
    *,
    waiting_message: str,
    ready_message: str,
    timeout_message: str,
    max_wait: int,
    poll_interval: int,
) -> None:
    """
    Poll check_fn() (expected to raise on failure) until it succeeds or
    max_wait seconds elapse, printing a "." per attempt in the meantime.
    Exits the process via timeout_message if it never becomes ready.
    """
    print(waiting_message, end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            check_fn()
            print(ready_message)
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(poll_interval)
    print()
    sys.exit(timeout_message)


def upsert_env_var(path: Path, key: str, value: str, header_lines: list[str]) -> bool:
    """
    Insert/update KEY=value in a dotenv-style file, preserving other lines.

    Replaces the active (non-commented) `KEY=` line if present; otherwise
    appends it, preceded by *header_lines* as comment lines. Returns True if
    an existing line was replaced, False if the key was newly appended.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    new_line = f"{key}={value}"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    replaced = False
    out: list[str] = []
    for line in existing:
        if line.lstrip().startswith(f"{key}=") and not line.lstrip().startswith("#"):
            out.append(new_line)
            replaced = True
        else:
            out.append(line)

    if not replaced:
        if out and out[-1].strip():
            out.append("")  # keep a blank line before the appended key
        out.extend(header_lines)
        out.append(new_line)

    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return replaced
