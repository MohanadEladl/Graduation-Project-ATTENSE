"""
permissions.py — Role & Permission Utilities
=============================================
Defines which analyst roles are authorized to perform which actions.

In a production system this would check against an auth service or JWT claims.
For the simulation, it provides a simple role-based guard.

Roles:
    analyst  → can investigate, deny, confirm, initiate containment
    senior   → all analyst rights + can complete containment
    system   → can raise alerts, end incidents (automated)
    admin    → all rights
"""

from __future__ import annotations

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "analyst": {
        "investigate_alert",
        "deny_alert",
        "confirm_incident",
        "initiate_containment",
    },
    "senior": {
        "investigate_alert",
        "deny_alert",
        "confirm_incident",
        "initiate_containment",
        "complete_containment",
    },
    "system": {
        "raise_alert",
        "end_incident",
        "start_incident",
    },
    "admin": {
        "investigate_alert",
        "deny_alert",
        "confirm_incident",
        "initiate_containment",
        "complete_containment",
        "raise_alert",
        "end_incident",
        "start_incident",
    },
}


def is_authorized(role: str, action: str) -> bool:
    """
    Check if a given role is authorized to perform an action.

    Parameters
    ----------
    role   : The analyst's role (analyst | senior | system | admin).
    action : The action being attempted (e.g. 'confirm_incident').

    Returns
    -------
    True if authorized, False otherwise.
    """
    allowed = ROLE_PERMISSIONS.get(role, set())
    return action in allowed


def require_permission(role: str, action: str) -> None:
    """
    Assert that a role has permission to perform an action.

    Raises
    ------
    PermissionError : If the role is not authorized.
    """
    if not is_authorized(role, action):
        raise PermissionError(
            f"Role '{role}' is not authorized to perform '{action}'."
        )
