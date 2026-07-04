"""
isolation_manager.py — Host Isolation Manager
===============================================
Handles full host network isolation — the most drastic containment action.
Used for Command Injection and severe compromises where the host must
be cut off from the network entirely.
"""

from __future__ import annotations

import logging

from .target_connector import TargetConnector

logger = logging.getLogger(__name__)


class IsolationManager:
    """
    Manages host isolation actions in the sandbox.

    Parameters
    ----------
    connector : TargetConnector for sending commands to the sandbox.
    """

    def __init__(self, connector: TargetConnector) -> None:
        self.connector = connector

    def isolate_host(self, target_id: str) -> dict:
        """
        Fully isolate a host from the network.

        Used for: Command Injection, severe malware, lateral movement.
        Side-effect: All network traffic to/from the host is blocked.

        Returns sandbox response dict.
        """
        logger.info("[IsolationManager] Isolating host: %s", target_id)
        return self.connector.execute_containment(target_id, "isolate_host")

    def restrict_access(self, target_id: str) -> dict:
        """
        Restrict access to a resource without full isolation.

        Used for: Directory Traversal — limit file system access paths.
        """
        logger.info("[IsolationManager] Restricting access for: %s", target_id)
        return self.connector.execute_containment(target_id, "restrict_access")
