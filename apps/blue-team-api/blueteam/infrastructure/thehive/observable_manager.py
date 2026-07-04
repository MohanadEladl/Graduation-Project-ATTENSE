"""
observable_manager.py — Hive Observable Manager
=================================================
Manages IOC (Indicator of Compromise) observables within Hive cases.
Provides convenience methods for common observable types encountered
in the simulation scenarios.
"""

from __future__ import annotations

import logging

from .hive_client import HiveClient

logger = logging.getLogger(__name__)


class ObservableManager:
    """
    Handles adding observables (IOCs) to Hive cases.

    Observable types supported:
        ip       → source/destination IP address
        domain   → suspicious domain
        url      → malicious URL
        hash     → file hash (MD5, SHA256)
        filename → malicious file name
        hostname → affected hostname
    """

    def __init__(self, hive: HiveClient) -> None:
        self.hive = hive

    def add_ip(self, case_id: str, ip_address: str) -> None:
        """Add a suspicious IP address as an observable."""
        self.hive.add_observable(case_id, "ip", ip_address)
        logger.info("[ObservableManager] IP observable added: %s", ip_address)

    def add_url(self, case_id: str, url: str) -> None:
        """Add a malicious URL as an observable."""
        self.hive.add_observable(case_id, "url", url)
        logger.info("[ObservableManager] URL observable added: %s", url)

    def add_hostname(self, case_id: str, hostname: str) -> None:
        """Add an affected hostname as an observable."""
        self.hive.add_observable(case_id, "hostname", hostname)
        logger.info("[ObservableManager] Hostname observable added: %s", hostname)

    def add_file_hash(self, case_id: str, file_hash: str) -> None:
        """Add a file hash as an observable."""
        self.hive.add_observable(case_id, "hash", file_hash)
        logger.info("[ObservableManager] Hash observable added: %s", file_hash)
