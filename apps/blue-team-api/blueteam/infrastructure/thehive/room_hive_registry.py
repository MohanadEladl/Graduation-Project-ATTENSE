"""
room_hive_registry.py - Per-Room TheHive API Key Lookup
=========================================================
Resolves the TheHive API key a given room should use, so alerts/cases for
room A land in room A's own TheHive organisation instead of one shared org
visible to every room (see apps/control-api/core/room_manager.py's
`_ensure_room_hive`, which provisions that per-room org + key).

Only works when this package runs EMBEDDED inside control-api's process
(apps/control-api/controller.py starts blueteam.main:app in a background
thread in the same container) - that's the only deployment where `core` is
on the PYTHONPATH. The standalone per-room container built from
apps/blue-team-api/Dockerfile has no `core` package, so the lookup below
fails there and every caller falls back to the global HIVE_API_KEY, matching
the pre-existing shared-org behaviour.
"""

from __future__ import annotations

import importlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def resolve_room_hive_api_key(room_id: Optional[str]) -> Optional[str]:
    """Return this room's own TheHive API key, or None if unavailable.

    None means "use the caller's fallback (global HIVE_API_KEY)" - either
    because there's no room_id (e.g. a room-less/system incident), the room
    hasn't been provisioned with its own key yet (no Blue Team member has
    entered it), or `core.room_manager` isn't importable (standalone
    deployment).
    """
    if not room_id or room_id == "system":
        return None
    room = _get_room(room_id)
    return room.get("hive_api_key") if room else None


def room_hive_org_pending(room_id: Optional[str]) -> bool:
    """True when *room_id* is a real, known room whose own dedicated Hive org
    hasn't been provisioned yet (nobody has entered it - see
    core.room_manager._ensure_room_hive), as opposed to there being no room
    at all (room_id is None/"system") or the room being genuinely unknown.

    Callers use this to distinguish "route into the shared fallback org is
    fine" (no room context to isolate) from "this write belongs to a specific
    room that just isn't ready yet" (routing it into the shared org would be
    the exact cross-room leak this registry exists to prevent - it should be
    skipped instead, and picked up later by that room's own /replay-alerts
    call once its org exists).
    """
    if not room_id or room_id == "system":
        return False
    room = _get_room(room_id)
    return room is not None and not room.get("hive_api_key")


def resolve_room_owner(room_id: Optional[str]) -> Optional[str]:
    """Return the username recorded as this room's soc_manager_username (the
    analyst who started/entered it - the room's owner for solo exercises),
    or None if unavailable. Same embedded-only caveat as
    resolve_room_hive_api_key above.
    """
    if not room_id or room_id == "system":
        return None
    room = _get_room(room_id)
    return room.get("soc_manager_username") if room else None


def _get_room(room_id: str) -> Optional[dict]:
    try:
        _rm = importlib.import_module("core.room_manager")
        get_room = _rm.get_room  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        return None
    try:
        return get_room(room_id)
    except Exception:
        logger.debug("[room_hive_registry] No room '%s' found", room_id)
        return None
