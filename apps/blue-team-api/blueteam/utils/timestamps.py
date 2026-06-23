"""
timestamps.py — Timestamp Utilities
======================================
Helper functions for timestamp calculation and formatting.
Used by metrics and reporting layers to compute TTD and TTC.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def seconds_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    """
    Calculate elapsed seconds between two timestamps.

    Parameters
    ----------
    start : Start datetime (e.g. incident start_time or detection_time).
    end   : End datetime (e.g. confirmation or containment timestamp).

    Returns
    -------
    Elapsed seconds as float, or None if either timestamp is missing.
    """
    if start is None or end is None:
        return None
    # Normalize both to naive UTC for comparison
    s = start.replace(tzinfo=None)
    e = end.replace(tzinfo=None)
    return (e - s).total_seconds()


def calculate_ttd(incident) -> Optional[float]:
    """
    Calculate Time to Detect (TTD) for an incident.

    TTD = detection_time − start_time (seconds)

    A shorter TTD means the Blue Team detected the attack faster.
    """
    return seconds_between(incident.start_time, incident.detection_time)


def calculate_ttc(incident) -> Optional[float]:
    """
    Calculate Time to Contain (TTC) for an incident.

    TTC = containment_time − detection_time (seconds)

    A shorter TTC means the Blue Team contained the threat faster.
    """
    return seconds_between(incident.detection_time, incident.containment_time)


def format_iso(dt: Optional[datetime]) -> Optional[str]:
    """Return ISO-8601 string for a datetime, or None if dt is None."""
    return dt.isoformat() if dt else None
