"""
abuseipdb_client.py — AbuseIPDB API v2 Client
===============================================
Performs IP reputation lookups against AbuseIPDB.

Returns the abuse confidence score (0–100 %), total reports,
country, ISP, usage type, and a computed risk label.

Graceful degradation: if ABUSEIPDB_API_KEY is empty or the API is
unreachable, returns an empty AbuseIPResult. The alert workflow is
never blocked by enrichment failures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseIPResult:
    """Structured AbuseIPDB lookup result."""

    ip: str = ""
    found: bool = False
    is_public: bool = True
    abuse_confidence_score: int = 0     # 0–100 %
    total_reports: int = 0
    num_distinct_users: int = 0
    country_code: str = ""
    isp: str = ""
    domain: str = ""
    usage_type: str = ""                # "Data Center/Web Hosting", "Fixed Line ISP", …
    is_whitelisted: bool = False
    error: str = ""                     # set if lookup failed

    @property
    def risk_label(self) -> str:
        """Risk classification based on AbuseIPDB confidence score."""
        if not self.found:
            return "unknown"
        if self.abuse_confidence_score >= 50:
            return "high"
        if self.abuse_confidence_score >= 20:
            return "medium"
        return "low"

    @property
    def summary(self) -> str:
        """One-line human-readable summary for the alert enrichment panel."""
        if not self.found:
            return "No AbuseIPDB data."
        return (
            f"Confidence: {self.abuse_confidence_score}% | "
            f"Reports: {self.total_reports} | "
            f"ISP: {self.isp or 'unknown'} | "
            f"Country: {self.country_code or 'unknown'}"
        )


class AbuseIPDBClient:
    """
    Thin client for the AbuseIPDB API v2.

    Parameters
    ----------
    api_key : AbuseIPDB API key. Empty string disables lookups.
    timeout : HTTP request timeout in seconds.
    max_age_in_days : How far back to look for reports (default 90 days).
    """

    def __init__(
        self,
        api_key: str = "",
        timeout: float = 10.0,
        max_age_in_days: int = 90,
    ) -> None:
        self._api_key = api_key.strip()
        self._timeout = timeout
        self._max_age = max_age_in_days
        self._enabled = bool(self._api_key)
        if not self._enabled:
            logger.info("[AbuseIPDB] No API key configured — IP lookups disabled.")

    # ──────────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────────

    def lookup(self, ip: str) -> AbuseIPResult:
        """
        Look up an IP address on AbuseIPDB.

        Parameters
        ----------
        ip : IPv4 or IPv6 address to check.

        Returns
        -------
        AbuseIPResult with abuse score, report count, and metadata.
        """
        if not self._enabled:
            return AbuseIPResult(ip=ip, error="no_api_key")

        # Skip obviously private/local addresses — AbuseIPDB won't know them
        if self._is_private(ip):
            logger.debug("[AbuseIPDB] Skipping private IP: %s", ip)
            return AbuseIPResult(ip=ip, is_public=False, found=False)

        try:
            resp = httpx.get(
                f"{_ABUSE_BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": self._max_age, "verbose": ""},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ip)
        except httpx.TimeoutException:
            logger.warning("[AbuseIPDB] Timeout looking up %s", ip)
            return AbuseIPResult(ip=ip, error="timeout")
        except Exception as exc:
            logger.warning("[AbuseIPDB] Lookup failed for %s: %s", ip, exc)
            return AbuseIPResult(ip=ip, error=str(exc))

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse(data: dict, ip: str) -> AbuseIPResult:
        """Parse raw AbuseIPDB API response into an AbuseIPResult."""
        d = data.get("data", {})
        return AbuseIPResult(
            ip=ip,
            found=True,
            is_public=d.get("isPublic", True),
            abuse_confidence_score=d.get("abuseConfidenceScore", 0),
            total_reports=d.get("totalReports", 0),
            num_distinct_users=d.get("numDistinctUsers", 0),
            country_code=d.get("countryCode", ""),
            isp=d.get("isp", ""),
            domain=d.get("domain", ""),
            usage_type=d.get("usageType", ""),
            is_whitelisted=d.get("isWhitelisted", False),
        )

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Return True for RFC-1918, loopback, and link-local addresses."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
