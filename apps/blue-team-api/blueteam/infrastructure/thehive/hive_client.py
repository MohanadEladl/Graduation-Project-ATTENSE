"""
hive_client.py - TheHive Integration Client
=============================================
Handles all communication with TheHive case management platform.

In production this sends real HTTP requests to the Hive API.
In development/testing it logs calls without hitting the network
when HIVE_URL is not set or unreachable.
"""

from __future__ import annotations

import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)
ATTENSE_BLUE_URL = os.getenv('ATTENSE_BLUE_URL', 'http://127.0.0.1:3100').rstrip('/')

# The analyst's "back to the ATTENSE report" control inside TheHive. The marker
# string appears in every alert/case description; ensure_return_link() dedups a
# case's description block on it, and the task carries the same wording.
RETURN_LINK_MARKER = "Return to ATTENSE report dashboard"
RETURN_TASK_TITLE = "⬅ Return to ATTENSE report"

# Cases that already got their "Return to ATTENSE report" task in this process.
# HiveClient is instantiated per-request (see api.dependencies.get_hive_client),
# so the dedup guard must live at module scope, not on the instance - otherwise
# the auto-promote and CaseCreated-webhook paths would each add the task.
_RETURN_LINKED_CASES: set[str] = set()


class HiveClient:
    """
    Client for TheHive case management API.

    Parameters
    ----------
    base_url : Base URL of the Hive instance (e.g. http://localhost:9000).
    api_key : Hive API key for authentication.
    timeout : HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9000",
        api_key: str = "",
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self.timeout = timeout
        # No api_key means "deliberately disabled" (see
        # dependencies.build_hive_client_for_room): a room whose own Hive org
        # isn't provisioned yet, where writing through some OTHER org's key
        # would leak this incident's data into the wrong org. _get/_post
        # short-circuit to a clean no-op instead of making that call.
        self._enabled = bool(api_key)

    def create_case(self, incident_id: str, title: str, severity: str) -> dict:
        """
        Create a new case in TheHive for the given incident.

        Parameters
        ----------
        incident_id : Internal incident identifier.
        title : Case title displayed in Hive.
        severity : One of low | medium | high | critical.

        Returns
        -------
        The Hive API response dict, or an empty dict on failure.
        """
        return_url = f"{ATTENSE_BLUE_URL}/?view=reports&incidentId={incident_id}"
        payload = {
            "title": title,
            "description": f"### ⬅ [Return to ATTENSE report dashboard]({return_url})\n\nAutomated case for incident {incident_id}",
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
        enrichment_summary: str = "",
        source_ref: str | None = None,
    ) -> dict:
        """
        Create a new alert in TheHive.

        Parameters
        ----------
        incident_id : Internal incident identifier.
        title : Alert title.
        severity : One of low | medium | high | critical.
        artifacts : List of observable dicts.
        enrichment_summary : Cortex-Lite's human-readable threat-intel summary
                               (AbuseIPDB/VirusTotal), appended to the alert
                               description so it's visible at a glance.
        """
        return_url = f"{ATTENSE_BLUE_URL}/?view=reports&incidentId={incident_id}"
        # The analyst's "back to report" control lives here: TheHive has no custom
        # buttons, so the alert description's first line is an unmistakable H2 link
        # (the marker string is what ensure_return_link dedups a case on).
        description = (
            f"## ⬅ [{RETURN_LINK_MARKER} — click here]({return_url})\n\n"
            f"---\n\nAutomated alert for incident {incident_id}"
        )
        if enrichment_summary:
            description += f"\n\nThreat intel summary: {enrichment_summary}"
        # TheHive dedups alerts by (type, source, sourceRef). Use a unique
        # sourceRef per detection so every Wazuh detection surfaces as its own
        # alert, while the incident tag keeps them grouped/searchable.
        payload = {
            "title": title,
            "description": description,
            "severity": self._map_severity(severity),
            "tags": [incident_id, f"attense:incident-{incident_id}"],
            "type": "siem",
            "source": "wazuh",
            "sourceRef": source_ref or f"{incident_id}-{uuid.uuid4().hex[:10]}",
            "artifacts": artifacts,
        }
        return self._post("/api/alert", payload)

    def update_case_severity(self, incident_id: str, severity: str) -> dict:
        """
        Update the severity of an existing Hive case by finding it via tags.
        """
        logger.info(
            "[HiveClient] Updating case severity for incident '%s' -> %s",
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

    def promote_alert_to_case(self, alert_id: str) -> dict:
        """
        Promote an existing TheHive alert into a case (alert -> case).

        Mirrors the analyst's "Import alert as case" action. The new case
        inherits the alert's tags (incl. attense:incident-<id>), so the
        CaseCreated webhook fires and the attacker activity log is attached.

        Returns the Hive API response dict (the new case), or {} on failure.
        """
        return self._post(f"/api/alert/{alert_id}/createCase", {})

    def ensure_return_link(self, case_id: str, incident_id: str) -> bool:
        """
        Guarantee the case gives the analyst a visible way back to the ATTENSE
        Blue Team report: a link block at the TOP of the case description plus
        a dedicated '⬅ Return to ATTENSE report' task in the case's task list.

        TheHive has no custom UI buttons, so these two markdown surfaces are
        the "button". Both are made idempotent independently:
        - the description block is prepended only when the marker is absent (a
          case promoted from an alert already inherits the alert's link, so this
          is usually a no-op - but that must NOT suppress the task below);
        - the task is created once per case per process, guarded by an in-memory
          set (HiveClient is built per-request, so the guard is module-level).
          A rare duplicate after a process restart is harmless.

        Returns True if anything was added, False if fully skipped/failed.
        """
        if not case_id:
            return False
        case = self._get(f"/api/case/{case_id}")
        if not isinstance(case, dict) or not case:
            # Can't read the current description; patching blind would erase it.
            logger.warning(
                "[HiveClient] Could not fetch case %s to add the return link.", case_id
            )
            return False

        return_url = f"{ATTENSE_BLUE_URL}/?view=reports&incidentId={incident_id}"
        added = False

        description = case.get("description") or ""
        if RETURN_LINK_MARKER not in description:
            link_block = f"### ⬅ [{RETURN_LINK_MARKER}]({return_url})"
            self._patch(
                f"/api/case/{case_id}",
                {"description": f"{link_block}\n\n{description}".strip()},
            )
            added = True

        if case_id not in _RETURN_LINKED_CASES:
            self._post(
                f"/api/case/{case_id}/task",
                {
                    "title": RETURN_TASK_TITLE,
                    "group": "attense",
                    "description": (
                        "When the investigation is done, open the ATTENSE Blue Team "
                        f"report for this incident:\n\n[{RETURN_LINK_MARKER}]({return_url})\n\n"
                        "Then use **Finish Incident & View Report** in the ATTENSE portal "
                        "to close the exercise and generate the scored report."
                    ),
                },
            )
            _RETURN_LINKED_CASES.add(case_id)
            added = True

        return added

    def add_observable(self, case_id: str, data_type: str, value: str) -> dict:
        """
        Add an observable (IOC) to a Hive case.

        Parameters
        ----------
        case_id : Hive case ID.
        data_type : Observable type (ip, domain, hash, etc.).
        value : Observable value.
        """
        payload = {
            "dataType": data_type,
            "data": value,
        }
        return self._post(f"/api/case/{case_id}/artifact", payload)

    def create_task(self, case_id: str, title: str, group: str = "investigation") -> dict:
        """
        Create a task on a Hive case.

        Used to hold the chronological "Attacker Activity Log" - each attacker
        action is later appended as a task log via ``add_task_log``.

        Returns the Hive API response dict (includes the new task ``id``), or
        an empty dict on failure.
        """
        payload = {
            "title": title,
            "group": group,
            "status": "InProgress",
        }
        return self._post(f"/api/case/{case_id}/task", payload)

    def add_task_log(self, task_id: str, message: str) -> dict:
        """
        Append a log entry to an existing Hive task.

        Parameters
        ----------
        task_id : Hive task ID (from ``create_task``).
        message : Free-text log line (markdown supported by Hive).
        """
        payload = {"message": message}
        return self._post(f"/api/case/task/{task_id}/log", payload)

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _get(self, path: str) -> list | dict:
        """Send a GET request to the Hive API. Returns [] or {} on error."""
        if not self._enabled:
            logger.info("[HiveClient] Skipping GET %s - client is disabled (no Hive org for this write yet).", path)
            return []
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
        if not self._enabled:
            logger.info("[HiveClient] Skipping POST %s - client is disabled (no Hive org for this write yet).", path)
            return {}
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
        if not self._enabled:
            logger.info("[HiveClient] Skipping PATCH %s - client is disabled (no Hive org for this write yet).", path)
            return {}
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
        """Map string severity to Hive numeric severity (1-4)."""
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            severity.lower(), 2
        )
