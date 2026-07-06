"""Shared read-only lookup for the file-based session store.

control-api's core/session_store.py owns session lifecycle (create/delete)
and is the only writer. This module only reads a session by token, so
blue-team-api - which shares control-api's /attense/temp volume when run
embedded in the same container, and still needs role information when run
standalone - can resolve the calling analyst's role without importing
control-api's `core` package (the standalone blue-team-api image only ships
`blueteam` + `attense_core`, not `core`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
SESSIONS_DIR = Path(TEMP_PATH) / "sessions"


def get_session(token: str) -> Optional[dict]:
    """Return the session dict for *token*, or None if missing/invalid."""
    if not token:
        return None
    path = SESSIONS_DIR / f"{token}.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
