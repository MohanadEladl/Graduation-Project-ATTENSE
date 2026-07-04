"""
firewall_manager.py — Firewall / Request Manager
==================================================
Handles network-level and application-level blocking.
Used for XSS and Directory Traversal containment strategies.
"""

from __future__ import annotations

import logging

from infrastructure.sandbox.target_connector import TargetConnector

logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Manages firewall rules and request blocking on the sandbox.

    Parameters
    ----------
    connector : TargetConnector for sending commands to the sandbox.
    """

    def __init__(self, connector: TargetConnector) -> None:
        self.connector = connector

    def block_request(self, target_id: str) -> dict:
        """
        Block malicious requests at the application/WAF level.

        Used for: XSS — block the injected script request.
        """
        logger.info("[FirewallManager] Blocking requests for target: %s", target_id)
        return self.connector.execute_containment(target_id, "block_request")

    def block_path(self, target_id: str) -> dict:
        """
        Block access to a specific file path.

        Used for: Directory Traversal — block the traversed path pattern.
        """
        logger.info("[FirewallManager] Blocking path for target: %s", target_id)
        return self.connector.execute_containment(target_id, "block_path")

    def disable_endpoint(self, target_id: str) -> dict:
        """
        Disable a vulnerable application endpoint entirely.

        Used for: XSS — take the vulnerable endpoint offline.
        """
        logger.info("[FirewallManager] Disabling endpoint for target: %s", target_id)
        return self.connector.execute_containment(target_id, "disable_endpoint")
