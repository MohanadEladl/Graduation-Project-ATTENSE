"""
case_manager.py — Hive Case Manager
=====================================
Higher-level orchestration on top of HiveClient.
Manages the full Hive case lifecycle tied to an incident.
"""

from __future__ import annotations

import logging

from infrastructure.thehive.hive_client import HiveClient

logger = logging.getLogger(__name__)


class CaseManager:
    """
    Manages TheHive case lifecycle for incidents.

    Responsibilities:
    - Open a new Hive case when an incident is confirmed
    - Add observables (IOCs) discovered during investigation
    - Close the case when incident ends

    Parameters
    ----------
    hive : HiveClient instance for API communication.
    """

    def __init__(self, hive: HiveClient) -> None:
        self.hive = hive
        self._case_ids: dict[str, str] = {}   # incident_id → hive_case_id

    def open_case(self, incident_id: str, title: str, severity: str) -> str | None:
        """
        Open a new Hive case for a confirmed incident.

        Returns the Hive case ID, or None if the API call failed.
        """
        result = self.hive.create_case(incident_id, title, severity)
        case_id = result.get("id")
        if case_id:
            self._case_ids[incident_id] = case_id
            logger.info(
                "[CaseManager] Case opened in Hive: case_id=%s for incident '%s'.",
                case_id, incident_id,
            )
        return case_id

    def add_ioc(self, incident_id: str, data_type: str, value: str) -> None:
        """
        Add an indicator of compromise to the Hive case for this incident.

        Parameters
        ----------
        incident_id : Incident whose case receives the observable.
        data_type   : Observable type (e.g. ip, domain, hash, url).
        value       : The IOC value.
        """
        case_id = self._case_ids.get(incident_id)
        if not case_id:
            logger.warning(
                "[CaseManager] No Hive case found for incident '%s' — IOC not added.",
                incident_id,
            )
            return
        self.hive.add_observable(case_id, data_type, value)
        logger.info(
            "[CaseManager] IOC added to case %s: %s=%s", case_id, data_type, value
        )
