"""
process_controller.py — Process Controller
============================================
Handles process-level containment actions.
Used for Command Injection attacks where a malicious process must be killed
or a vulnerable service disabled.
"""

from __future__ import annotations

import logging

from .target_connector import TargetConnector

logger = logging.getLogger(__name__)


class ProcessController:
    """
    Controls processes on the sandbox target.

    Parameters
    ----------
    connector : TargetConnector for sending commands to the sandbox.
    """

    def __init__(self, connector: TargetConnector) -> None:
        self.connector = connector

    def kill_process(self, target_id: str) -> dict:
        """
        Kill a malicious or compromised process on the target.

        Used for: Command Injection — terminate spawned shell/process.
        """
        logger.info("[ProcessController] Killing process on target: %s", target_id)
        return self.connector.execute_containment(target_id, "kill_process")

    def disable_service(self, target_id: str) -> dict:
        """
        Disable a vulnerable or compromised service on the target.

        Used for: Command Injection — stop the service exploited by the attacker.
        """
        logger.info("[ProcessController] Disabling service on target: %s", target_id)
        return self.connector.execute_containment(target_id, "disable_service")
