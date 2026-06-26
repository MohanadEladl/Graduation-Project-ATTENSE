"""
identity.py — Analyst identity resolution for the Watcher Agent.

On startup:
  1. Check ~/.attense_identity for a cached analyst name.
     - If found: show it, let the user keep it or enter a new one.
     - If not found: prompt "Your name:".
  2. Sanitize to analyst-<slug> format and save to cache.
  3. Prompt "Session code:".
  4. Return (analyst_id, session_code).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_IDENTITY_FILE = Path.home() / ".attense_identity"


def _slugify(name: str) -> str:
    """Lower-case, replace spaces/special chars with hyphens, collapse runs."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    return slug or "analyst"


def resolve_identity() -> tuple[str, str]:
    """
    Interactively resolve the analyst identity and session code.

    Returns
    -------
    (analyst_id, session_code)
        analyst_id  — "analyst-<slug>" format
        session_code — 6-character uppercase code typed by the analyst
    """
    # Non-interactive fast path: env vars allow Docker/CI startup without prompts.
    env_id = os.getenv("ANALYST_ID", "").strip()
    env_code = os.getenv("SESSION_CODE", "").strip().upper()
    if env_id and env_code:
        print(f"Identity from env: {env_id}  session: {env_code}")
        return env_id, env_code

    cached = _read_cache()

    if cached:
        print(f"\nWelcome back, {cached}")
        raw = input("Press Enter to keep this name, or type a new one: ").strip()
        name = raw if raw else _extract_name(cached)
    else:
        name = input("\nYour name: ").strip()
        while not name:
            name = input("Name cannot be empty. Your name: ").strip()

    analyst_id = f"analyst-{_slugify(name)}"
    _write_cache(analyst_id)
    print(f"Identity set: {analyst_id}")

    session_code = input("Session code: ").strip().upper()
    while len(session_code) != 6:
        session_code = input("Code must be 6 characters. Session code: ").strip().upper()

    return analyst_id, session_code


def _read_cache() -> str | None:
    try:
        return _IDENTITY_FILE.read_text().strip() or None
    except OSError:
        return None


def _write_cache(analyst_id: str) -> None:
    try:
        _IDENTITY_FILE.write_text(analyst_id)
    except OSError:
        pass  # non-fatal — cache is a convenience, not a requirement


def _extract_name(analyst_id: str) -> str:
    """Strip the 'analyst-' prefix to recover the display name for re-slugifying."""
    return analyst_id.removeprefix("analyst-")
