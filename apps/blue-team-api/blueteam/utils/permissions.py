"""Role authorization checks.

Grant/revoke mutation helpers live in sibling modules:
    - grant_permissions.py
    - revoke_permissions.py
"""

from __future__ import annotations

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "ciso": {
        "view_all_companies",
        "view_all_reports",
        "manage_permissions",
    },
    "soc_manager": {
        "create_rooms",
        "start_blue_team",
        "manage_hive_keys",
        "investigate_alerts",
        "confirm_incidents",
        "start_containment",
        "complete_containment",
        "review_reports",
    },
    "soc_l1": {
        "investigate_alerts",
        "confirm_incidents",
        "start_containment",
    },
    "soc_l2": {
        "investigate_alerts",
        "confirm_incidents",
        "start_containment",
        "complete_containment",
        "review_reports",
    },
    "red_team": {
        "join_rooms",
        "create_attacks",
    },
    "system": {
        "raise_alert",
        "end_incident",
        "start_incident",
    },
    "admin": {
        "view_all_companies",
        "view_all_reports",
        "manage_permissions",
        "create_rooms",
        "start_blue_team",
        "manage_hive_keys",
        "investigate_alerts",
        "confirm_incidents",
        "start_containment",
        "complete_containment",
        "review_reports",
        "join_rooms",
        "create_attacks",
        "raise_alert",
        "end_incident",
        "start_incident",
    },
}


def is_authorized(role: str, action: str) -> bool:
    """Return whether a role may perform an action."""
    return action in ROLE_PERMISSIONS.get(role, set())


def require_permission(role: str, action: str) -> None:
    """Raise PermissionError when the role cannot perform the action."""
    if not is_authorized(role, action):
        raise PermissionError(
            f"Role '{role}' is not authorized to perform '{action}'."
        )
