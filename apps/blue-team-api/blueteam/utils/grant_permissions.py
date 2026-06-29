"""Permission grant helpers."""

from __future__ import annotations

from typing import MutableMapping


def grant_permission(
    role: str,
    action: str,
    permissions: MutableMapping[str, set[str]],
) -> bool:
    """Grant one action to a role and return whether the mapping changed."""
    allowed = permissions.setdefault(role, set())
    before = len(allowed)
    allowed.add(action)
    return len(allowed) != before
