"""
core/logger.py — Structured logging for the Red Team framework (CLI build).

Pure-Python implementation: NO Qt/PySide6 dependency so the container runs
headless. Writes JSONL entries to /red-team/logs/attack_log.jsonl and echoes
to stdout with ANSI colors for live operator feedback.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Callable, List

from core.models import AttackResult

# ── Log file location ─────────────────────────────────────────────────────────
LOG_DIR = os.environ.get(
    "LOG_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"),
)
LOG_FILE = os.path.join(LOG_DIR, "attack_log.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)

# ── ANSI colors (disabled if NO_COLOR env or non-TTY) ─────────────────────────
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


class LogManager:
    """
    Central log manager. Broadcast-style: callbacks can subscribe to every
    line for live rendering (e.g. a future web UI). CLI mode just prints.
    """

    def __init__(self) -> None:
        self._subscribers: List[Callable[[str], None]] = []
        self._result_subscribers: List[Callable[[dict], None]] = []

    # ── Subscription API (kept for compatibility with future UIs) ─────────────
    def subscribe(self, fn: Callable[[str], None]) -> None:
        self._subscribers.append(fn)

    def subscribe_result(self, fn: Callable[[dict], None]) -> None:
        self._result_subscribers.append(fn)

    # ── Private emit helper ───────────────────────────────────────────────────
    def _emit(self, line: str) -> None:
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            # Windows consoles may use a narrow encoding (cp1256, etc.)
            # Fall back to ASCII-safe output so the execute thread never crashes.
            safe = line.encode(sys.stdout.encoding or "ascii", "replace").decode(sys.stdout.encoding or "ascii")
            print(safe, flush=True)
        for cb in self._subscribers:
            try:
                cb(line)
            except Exception:
                pass

    # ── Public log methods ────────────────────────────────────────────────────
    def info(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._emit(f"[{ts}] {msg}")

    def success(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._emit(f"[{ts}] {_c('32', '✓')} {msg}")

    def error(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._emit(f"[{ts}] {_c('31', '✗')} {msg}")

    def warning(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._emit(f"[{ts}] {_c('33', '⚠')} {msg}")

    # ── Persistent log of completed attacks ───────────────────────────────────
    def log_result(self, result: AttackResult) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **result.to_dict(),
        }
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            self.error(f"Failed to write log: {exc}")

        for cb in self._result_subscribers:
            try:
                cb(entry)
            except Exception:
                pass

        ok = result.successful_steps
        total = result.total_steps
        self.info(
            f"[{result.module_name}] Complete — {ok}/{total} steps OK | "
            f"{result.duration_ms:.0f}ms | {result.summary}"
        )
