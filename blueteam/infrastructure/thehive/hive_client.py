"""
hive_client.py — TheHive Integration Client
=============================================
Handles all communication with TheHive case management platform.

In production this sends real HTTP requests to the Hive API.
In development/testing it logs calls without hitting the network
when HIVE_URL is not set or unreachable.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class HiveClient:
    """
    Client for TheHive case management API.

    Parameters
    ----------
    base_url : Base URL of the Hive instance (e.g. http://localhost:9000).
    api_key  : Hive API key for authentication.
    timeout  : HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9000",
        api_key: str = "",
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self.timeout = timeout

    def create_case(self, incident_id: str, title: str, severity: str) -> dict:
        """
        Create a new case in TheHive for the given incident.

        Parameters
        ----------
        incident_id : Internal incident identifier.
        title       : Case title displayed in Hive.
        severity    : One of low | medium | high | critical.

        Returns
        -------
        The Hive API response dict, or an empty dict on failure.
        """
        payload = {
            "title": title,
            "description": f"Automated case for incident {incident_id}",
            "severity": self._map_severity(severity),
            "tags": [incident_id, f"attense:incident-{incident_id}"],
        }
        return self._post("/api/case", payload)

    def create_alert(
        self,
        incident_id: str,
        title: str,
        severity: str,
        artifacts: list[dict],
    ) -> dict:
        """
        Create a new alert in TheHive.

        Parameters
        ----------
        incident_id : Internal incident identifier.
        title       : Alert title.
        severity    : One of low | medium | high | critical.
        artifacts   : List of observable dicts.
        """
        payload = {
            "title": title,
            "description": f"Automated alert for incident {incident_id}",
            "severity": self._map_severity(severity),
            "tags": [incident_id, f"attense:incident-{incident_id}"],
            "type": "siem",
            "source": "wazuh",
            "sourceRef": incident_id,
            "artifacts": artifacts,
        }
        return self._post("/api/alert", payload)

    def update_case_severity(self, incident_id: str, severity: str) -> dict:
        """
        Update the severity of an existing Hive case by finding it via tags.
        """
        logger.info(
            "[HiveClient] Updating case severity for incident '%s' → %s",
            incident_id, severity,
        )
        cases = self._get("/api/case")
        if not isinstance(cases, list):
            logger.warning("[HiveClient] Failed to retrieve case list from TheHive.")
            return {}

        target_case = None
        for case in cases:
            tags = case.get("tags", [])
            if incident_id in tags or f"attense:incident-{incident_id}" in tags:
                target_case = case
                break

        if not target_case:
            logger.warning(
                "[HiveClient] No case found in TheHive with tag containing incident_id '%s'",
                incident_id,
            )
            return {}

        case_id = target_case.get("id") or target_case.get("_id")
        if not case_id:
            logger.warning("[HiveClient] Case found but has no ID.")
            return {}

        payload = {"severity": self._map_severity(severity)}
        return self._patch(f"/api/case/{case_id}", payload)

    def add_observable(self, case_id: str, data_type: str, value: str) -> dict:
        """
        Add an observable (IOC) to a Hive case.

        Parameters
        ----------
        case_id   : Hive case ID.
        data_type : Observable type (ip, domain, hash, etc.).
        value     : Observable value.
        """
        payload = {
            "dataType": data_type,
            "data": value,
        }
        return self._post(f"/api/case/{case_id}/artifact", payload)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _get(self, path: str) -> list | dict:
        """Send a GET request to the Hive API. Returns [] or {} on error."""
        url = f"{self.base_url}{path}"
        try:
            response = httpx.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("[HiveClient] GET request to %s failed: %s", url, exc)
            return []

    def _post(self, path: str, payload: dict) -> dict:
        """Send a POST request to the Hive API. Returns {} on error."""
        url = f"{self.base_url}{path}"
        try:
            response = httpx.post(
                url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("[HiveClient] Request to %s failed: %s", url, exc)
            return {}

    def _patch(self, path: str, payload: dict) -> dict:
        """Send a PATCH request to the Hive API. Returns {} on error."""
        url = f"{self.base_url}{path}"
        try:
            response = httpx.patch(
                url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("[HiveClient] PATCH request to %s failed: %s", url, exc)
            return {}

    @staticmethod
    def _map_severity(severity: str) -> int:
        """Map string severity to Hive numeric severity (1–4)."""
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            severity.lower(), 2
        )
