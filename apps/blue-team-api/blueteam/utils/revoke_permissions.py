"""Permission revoke helpers."""

from __future__ import annotations

from typing import MutableMapping


def revoke_permission(
    role: str,
    action: str,
    permissions: MutableMapping[str, set[str]],
) -> bool:
    """Revoke one action from a role and return whether the mapping changed."""
    allowed = permissions.get(role)
    if not allowed or action not in allowed:
        return False
    allowed.remove(action)
    return True
