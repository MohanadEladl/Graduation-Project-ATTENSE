"""
utils.py – Shared helpers for ATTENSE Signal Mapper.

All functions are pure / side-effect-free and safe to call from any module.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """
    Deep-access a nested dict without raising KeyError / TypeError.

    Example::

        safe_get(alert, "rule", "description", default="")
    """
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is None:
            return default
    return current


def to_iso(ts: str) -> str:
    """
    Normalise a Wazuh timestamp string to a full ISO-8601 string.

    Wazuh produces strings like ``2026-02-22T01:00:00.000+0000`` which is
    almost ISO-8601 but the timezone offset lacks a colon.  We normalise to
    the RFC-3339 / ISO-8601 form ``2026-02-22T01:00:00.000+00:00``.

    If the timestamp is empty or unparseable the current UTC time is returned.
    """
    if not ts:
        return datetime.now(timezone.utc).isoformat()

    # Insert colon into ±HHMM offset → ±HH:MM
    ts_fixed = re.sub(r"([+-])(\d{2})(\d{2})$", r"\1\2:\3", ts.strip())

    try:
        dt = datetime.fromisoformat(ts_fixed)
        return dt.isoformat()
    except ValueError:
        pass

    # Fallback: return the original string (better than crashing)
    return ts


def truncate(s: str, n: int = 200) -> str:
    """Return at most *n* characters of *s*, appending '…' if truncated."""
    if not s:
        return ""
    return s[:n] + ("…" if len(s) > n else "")


def or_none(value: str) -> str | None:
    """Return *value* if non-empty/non-whitespace, else None."""
    stripped = (value or "").strip()
    return stripped if stripped else None
