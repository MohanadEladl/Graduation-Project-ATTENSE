"""
lab_evidence_connector.py — Target-Agent Evidence Reader
=========================================================
Read-only companion to TargetConnector (which sends containment commands).

The target-agent records every attacker interaction as a structured "lab
event" (recon, brute-force, XSS, command injection, traversal, upload, CSRF)
and exposes them at GET /lab/events. This connector fetches those events so
the Blue Team can attach the attacker's activity to a TheHive case.

Single responsibility: pull evidence. It does not mutate anything on the
target. All failures are non-fatal — a down target-agent yields [].
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class LabEvidenceConnector:
    """
    Fetches attacker evidence ("lab events") from the target-agent.

    Parameters
    ----------
    base_url : Base URL of the target-agent service (same as SANDBOX_URL).
    timeout  : HTTP request timeout in seconds.
    """

    def __init__(self, base_url: str = "http://localhost:8020", timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fetch_events(
        self,
        since_epoch: float = 0.0,
        source_ip: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """
        Fetch lab events recorded after *since_epoch*.

        The /lab/events endpoint filters by ``since``/``module_id``/``via`` but
        NOT by source IP, so the IP refinement is applied client-side here.

        Parameters
        ----------
        since_epoch : Only return events with ``ts >= since_epoch``.
        source_ip   : If given, keep only events from this attacker IP.
                      If None, return all events in the window.
        limit       : Max events to request from the target-agent.

        Returns
        -------
        List of event dicts (chronological), or [] on any failure.
        """
        url = f"{self.base_url}/lab/events"
        params = {"since": since_epoch, "limit": limit}
        try:
            response = httpx.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            events = response.json().get("events", [])
        except Exception as exc:
            logger.warning("[LabEvidenceConnector] Fetch from %s failed: %s", url, exc)
            return []

        if source_ip:
            events = [e for e in events if e.get("source_ip") == source_ip]

        events.sort(key=lambda e: e.get("ts", 0))
        logger.info(
            "[LabEvidenceConnector] Fetched %d lab events (since=%s, source_ip=%s)",
            len(events), since_epoch, source_ip or "*",
        )
        return events
