"""
target_connector.py — Sandbox Target Connector
================================================
The primary interface between the Blue Team service and the sandbox
(target-agent) environment.

Sends containment commands to the target machine via HTTP.
All containment strategies route through here.

Strategy → HTTP action mapping:
    kill_process      → POST /system/kill-process
    disable_service   → POST /system/disable-service
    isolate_host      → POST /system/isolate
    block_request     → POST /system/block-request
    remove_payload    → POST /system/remove-payload
    disable_endpoint  → POST /system/disable-endpoint
    block_path        → POST /system/block-path
    restrict_access   → POST /system/restrict-access
    lock_account      → POST /system/lock-account
    invalidate_session→ POST /system/invalidate-session
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

STRATEGY_ENDPOINT_MAP: dict[str, str] = {
    "kill_process":       "/system/kill-process",
    "disable_service":    "/system/disable-service",
    "isolate_host":       "/system/isolate",
    "block_request":      "/system/block-request",
    "remove_payload":     "/system/remove-payload",
    "disable_endpoint":   "/system/disable-endpoint",
    "block_path":         "/system/block-path",
    "restrict_access":    "/system/restrict-access",
    "lock_account":       "/system/lock-account",
    "invalidate_session": "/system/invalidate-session",
}


class TargetConnector:
    """
    Sends containment commands to the target sandbox environment.

    Parameters
    ----------
    base_url : Base URL of the target-agent service.
    timeout  : HTTP request timeout in seconds.
    """

    def __init__(self, base_url: str = "http://localhost:8020", timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def execute_containment(self, target_id: str, strategy: str | None) -> dict:
        """
        Send a containment command to the target sandbox.

        Parameters
        ----------
        target_id : ID of the resource to contain (host/service/account).
        strategy  : The containment strategy to apply.

        Returns
        -------
        Response dict from target-agent, or {} on failure.
        """
        if not strategy:
            logger.warning("[TargetConnector] No strategy specified — skipping sandbox call.")
            return {}

        endpoint = STRATEGY_ENDPOINT_MAP.get(strategy)
        if not endpoint:
            logger.warning("[TargetConnector] Unknown strategy '%s' — skipping.", strategy)
            return {}

        url = f"{self.base_url}{endpoint}"
        payload = {"target_id": target_id, "strategy": strategy}

        try:
            response = httpx.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            logger.info(
                "[TargetConnector] Containment executed: strategy=%s target=%s",
                strategy, target_id,
            )
            return response.json()
        except Exception as exc:
            logger.warning(
                "[TargetConnector] Sandbox call failed (strategy=%s target=%s): %s",
                strategy, target_id, exc,
            )
            return {}
