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
apps/blue-team-api/Dockerfile has no `core` package, so the import below
fails there and every caller falls back to the global HIVE_API_KEY, matching
the pre-existing shared-org behaviour.
"""

from __future__ import annotations

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
    try:
        from core.room_manager import get_room  # embedded-only import
    except ImportError:
        return None
    try:
        room = get_room(room_id)
    except Exception:
        logger.debug("[room_hive_registry] No room '%s' found for Hive key lookup", room_id)
        return None
    return room.get("hive_api_key") or None
