"""
virustotal_client.py — VirusTotal API v3 Client
=================================================
Performs threat intelligence lookups against VirusTotal for:
  - IP addresses  → malicious/suspicious votes, country, ASN
  - URLs          → malicious/suspicious vote counts
  - File hashes   → detection ratio, malware family names

Graceful degradation: if VT_API_KEY is empty or the API is
unreachable, returns an empty VTResult instead of raising an error.
The alert workflow is never blocked by enrichment failures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    """Structured VirusTotal lookup result."""

    ioc: str = ""
    ioc_type: str = ""                      # "ip", "url", "hash"
    found: bool = False
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    undetected_votes: int = 0
    total_engines: int = 0
    community_score: int = 0                # negative = bad
    country: str = ""
    asn: int = 0
    as_owner: str = ""
    malware_families: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    error: str = ""                         # set if lookup failed

    @property
    def detection_ratio(self) -> str:
        """Human-readable detection ratio, e.g. '34/72'."""
        if self.total_engines == 0:
            return "N/A"
        return f"{self.malicious_votes}/{self.total_engines}"

    @property
    def risk_label(self) -> str:
        """Simple risk classification based on malicious votes."""
        if not self.found or self.total_engines == 0:
            return "unknown"
        ratio = self.malicious_votes / self.total_engines
        if ratio >= 0.3:
            return "malicious"
        if ratio >= 0.05 or self.suspicious_votes > 2:
            return "suspicious"
        return "clean"


class VirusTotalClient:
    """
    Thin client for the VirusTotal API v3.

    Parameters
    ----------
    api_key : VirusTotal API key. Empty string disables lookups.
    timeout : HTTP request timeout in seconds.
    """

    def __init__(self, api_key: str = "", timeout: float = 10.0) -> None:
        self._api_key = api_key.strip()
        self._timeout = timeout
        self._enabled = bool(self._api_key)
        if not self._enabled:
            logger.info("[VT] No API key configured — VirusTotal lookups disabled.")

    # ──────────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> VTResult:
        """Look up an IP address on VirusTotal."""
        if not self._enabled:
            return VTResult(ioc=ip, ioc_type="ip", error="no_api_key")
        return self._get_report(f"/ip_addresses/{ip}", ip, "ip")

    def lookup_url(self, url: str) -> VTResult:
        """Look up a URL on VirusTotal (via URL identifier encoding)."""
        if not self._enabled:
            return VTResult(ioc=url, ioc_type="url", error="no_api_key")
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._get_report(f"/urls/{url_id}", url, "url")

    def lookup_hash(self, file_hash: str) -> VTResult:
        """Look up a file hash (MD5 / SHA1 / SHA256) on VirusTotal."""
        if not self._enabled:
            return VTResult(ioc=file_hash, ioc_type="hash", error="no_api_key")
        return self._get_report(f"/files/{file_hash}", file_hash, "hash")

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _get_report(self, path: str, ioc: str, ioc_type: str) -> VTResult:
        """Fetch a report from VT and parse it into a VTResult."""
        url = f"{_VT_BASE}{path}"
        headers = {"x-apikey": self._api_key}
        try:
            resp = httpx.get(url, headers=headers, timeout=self._timeout)
            if resp.status_code == 404:
                return VTResult(ioc=ioc, ioc_type=ioc_type, found=False)
            resp.raise_for_status()
            return self._parse(resp.json(), ioc, ioc_type)
        except httpx.TimeoutException:
            logger.warning("[VT] Timeout looking up %s", ioc)
            return VTResult(ioc=ioc, ioc_type=ioc_type, error="timeout")
        except Exception as exc:
            logger.warning("[VT] Lookup failed for %s: %s", ioc, exc)
            return VTResult(ioc=ioc, ioc_type=ioc_type, error=str(exc))

    @staticmethod
    def _parse(data: dict, ioc: str, ioc_type: str) -> VTResult:
        """Parse the raw VT API response into a VTResult."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Malware family names (files only)
        families: list[str] = []
        popular_threat = attrs.get("popular_threat_classification", {})
        for item in popular_threat.get("suggested_threat_label", "").split("."):
            if item:
                families.append(item)

        return VTResult(
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious_votes=malicious,
            suspicious_votes=suspicious,
            harmless_votes=harmless,
            undetected_votes=undetected,
            total_engines=total,
            community_score=attrs.get("reputation", 0),
            country=attrs.get("country", ""),
            asn=attrs.get("asn", 0),
            as_owner=attrs.get("as_owner", ""),
            malware_families=families,
            tags=attrs.get("tags", []),
        )
