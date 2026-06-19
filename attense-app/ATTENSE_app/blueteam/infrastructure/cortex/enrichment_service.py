"""
enrichment_service.py — Cortex-Lite Orchestrator
==================================================
Extracts IOCs from an incoming alert and runs all enrichment
lookups (VirusTotal + AbuseIPDB) in one place.

Called automatically by the raise_alert route — the analyst sees
enrichment results as part of the alert_raised response.

Design rules:
  - NEVER raises an exception (enrichment is best-effort)
  - NEVER blocks the alert workflow on failure
  - Returns EnrichmentReport with whatever data was collected
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field

from infrastructure.cortex.virustotal_client import VirusTotalClient, VTResult
from infrastructure.cortex.abuseipdb_client import AbuseIPDBClient, AbuseIPResult

logger = logging.getLogger(__name__)

# ── IOC extraction patterns ───────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_URL_RE  = re.compile(r"https?://[^\s\"'<>]+")


@dataclass
class EnrichmentReport:
    """
    Aggregated enrichment results for a single alert.

    Fields
    ------
    iocs_found      : dict of extracted IOC values by type
    ip_reputation   : AbuseIPDB results for every IP in the alert
    vt_ip_results   : VirusTotal results for every IP
    vt_url_results  : VirusTotal results for every URL
    vt_hash_results : VirusTotal results for every hash
    risk_score      : 0–100 overall risk estimate
    risk_label      : "low" | "medium" | "high" | "critical"
    enrichment_note : Human-readable summary for the analyst
    errors          : Any non-fatal errors during enrichment
    """

    iocs_found: dict[str, list[str]] = field(default_factory=dict)
    ip_reputation: list[AbuseIPResult] = field(default_factory=list)
    vt_ip_results: list[VTResult] = field(default_factory=list)
    vt_url_results: list[VTResult] = field(default_factory=list)
    vt_hash_results: list[VTResult] = field(default_factory=list)
    risk_score: int = 0
    risk_label: str = "unknown"
    enrichment_note: str = ""
    errors: list[str] = field(default_factory=list)

    def describe(self, value: str, ioc_type: str) -> tuple[str, list[str]]:
        """
        One-line message + TheHive tags summarizing reputation for a single
        IOC value, so the analyst sees real evidence on the observable itself
        instead of a generic "Attacker IP" placeholder.
        """
        parts: list[str] = []
        tags: list[str] = []
        vt_result = None

        if ioc_type == "ip":
            abuse = next((r for r in self.ip_reputation if r.ip == value), None)
            if abuse and abuse.found and not abuse.error:
                parts.append(
                    f"AbuseIPDB {abuse.abuse_confidence_score}% confidence "
                    f"({abuse.total_reports} reports, {abuse.country_code or '?'})"
                )
                tags.append(f"abuseipdb:{abuse.abuse_confidence_score}%")
            vt_result = next((r for r in self.vt_ip_results if r.ioc == value), None)
        elif ioc_type == "url":
            vt_result = next((r for r in self.vt_url_results if r.ioc == value), None)
        elif ioc_type == "hash":
            vt_result = next((r for r in self.vt_hash_results if r.ioc == value), None)

        if vt_result and vt_result.found:
            parts.append(f"VirusTotal {vt_result.detection_ratio} engines flagged malicious")
            tags.append(f"vt:{vt_result.detection_ratio}")

        if not parts:
            default_message = {
                "ip": "Attacker IP",
                "url": "Malicious URL",
                "hash": "Malicious File Hash",
            }.get(ioc_type, "Indicator")
            return f"{default_message} — no threat-intel match found", tags

        return " | ".join(parts), tags

    def to_dict(self) -> dict:
        """Serialise to a plain dict for embedding in ActionResponse."""
        return {
            "iocs_found": self.iocs_found,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "enrichment_note": self.enrichment_note,
            "ip_reputation": [
                {
                    "ip": r.ip,
                    "abuse_confidence_score": r.abuse_confidence_score,
                    "total_reports": r.total_reports,
                    "country": r.country_code,
                    "isp": r.isp,
                    "usage_type": r.usage_type,
                    "risk_label": r.risk_label,
                    "summary": r.summary,
                    "error": r.error,
                }
                for r in self.ip_reputation
            ],
            "virustotal": {
                "ips": [_vt_dict(r) for r in self.vt_ip_results],
                "urls": [_vt_dict(r) for r in self.vt_url_results],
                "hashes": [_vt_dict(r) for r in self.vt_hash_results],
            },
            "errors": self.errors,
        }


def _vt_dict(r: VTResult) -> dict:
    return {
        "ioc": r.ioc,
        "ioc_type": r.ioc_type,
        "found": r.found,
        "malicious_votes": r.malicious_votes,
        "suspicious_votes": r.suspicious_votes,
        "total_engines": r.total_engines,
        "detection_ratio": r.detection_ratio,
        "risk_label": r.risk_label,
        "country": r.country,
        "as_owner": r.as_owner,
        "malware_families": r.malware_families,
        "tags": r.tags,
        "error": r.error,
    }


class EnrichmentService:
    """
    Cortex-Lite: orchestrates all IOC enrichment for an incoming alert.

    Parameters
    ----------
    vt_api_key    : VirusTotal API key (empty = disabled).
    abuse_api_key : AbuseIPDB API key (empty = disabled).
    """

    def __init__(self, vt_api_key: str = "", abuse_api_key: str = "") -> None:
        self._vt    = VirusTotalClient(api_key=vt_api_key)
        self._abuse = AbuseIPDBClient(api_key=abuse_api_key)

    # ──────────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────────

    def enrich_alert(self, raw_log: str, siem_id: str = "", target_id: str = "") -> EnrichmentReport:
        """
        Extract IOCs from the alert's raw_log and enrich them.

        Parameters
        ----------
        raw_log   : The raw log line from the alert (best source of IOCs).
        siem_id   : SIEM alert ID — used as fallback IOC context.
        target_id : Target identifier — checked if it looks like an IP.

        Returns
        -------
        EnrichmentReport (never raises — always returns something).
        """
        report = EnrichmentReport()

        try:
            # 1. Extract IOCs from all available fields
            combined_text = " ".join(filter(None, [raw_log, siem_id, target_id]))
            iocs = self._extract_iocs(combined_text)
            report.iocs_found = {k: list(v) for k, v in iocs.items()}

            logger.info(
                "[Cortex] Enriching alert — IPs: %d, URLs: %d, Hashes: %d",
                len(iocs["ips"]), len(iocs["urls"]), len(iocs["hashes"]),
            )

            # 2. AbuseIPDB — check every extracted IP
            for ip in iocs["ips"]:
                result = self._abuse.lookup(ip)
                report.ip_reputation.append(result)
                if result.error:
                    report.errors.append(f"AbuseIPDB({ip}): {result.error}")

            # 3. VirusTotal — IPs
            for ip in iocs["ips"]:
                result = self._vt.lookup_ip(ip)
                report.vt_ip_results.append(result)
                if result.error and result.error != "no_api_key":
                    report.errors.append(f"VT_IP({ip}): {result.error}")

            # 4. VirusTotal — URLs
            for url in iocs["urls"]:
                result = self._vt.lookup_url(url)
                report.vt_url_results.append(result)
                if result.error and result.error != "no_api_key":
                    report.errors.append(f"VT_URL({url}): {result.error}")

            # 5. VirusTotal — Hashes
            for h in iocs["hashes"]:
                result = self._vt.lookup_hash(h)
                report.vt_hash_results.append(result)
                if result.error and result.error != "no_api_key":
                    report.errors.append(f"VT_Hash({h}): {result.error}")

            # 6. Compute overall risk score and label
            report.risk_score, report.risk_label = self._compute_risk(report)
            report.enrichment_note = self._make_note(report)

        except Exception as exc:
            logger.error("[Cortex] Unexpected enrichment error: %s", exc, exc_info=True)
            report.errors.append(f"unexpected: {exc}")
            report.enrichment_note = "Enrichment failed unexpectedly — alert still valid."

        return report

    # ──────────────────────────────────────────────────────────────────────────
    # IOC extraction
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_iocs(text: str) -> dict[str, set[str]]:
        """
        Extract IPs, URLs, and hashes from free-form text.
        Returns a dict of sets to avoid duplicates.
        """
        ips:    set[str] = set()
        urls:   set[str] = set()
        hashes: set[str] = set()

        # URLs first (so IPs inside URLs aren't double-counted)
        for url in _URL_RE.findall(text):
            urls.add(url)

        # IPs (skip those already captured inside URLs)
        url_text = " ".join(urls)
        for ip in _IPV4_RE.findall(text):
            if ip not in url_text:
                try:
                    # Validate it's a real IP (not e.g. a version number)
                    ipaddress.ip_address(ip)
                    ips.add(ip)
                except ValueError:
                    pass

        # Hashes
        for h in _HASH_RE.findall(text):
            hashes.add(h)

        return {"ips": ips, "urls": urls, "hashes": hashes}

    # ──────────────────────────────────────────────────────────────────────────
    # Risk scoring
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_risk(report: EnrichmentReport) -> tuple[int, str]:
        """
        Compute a 0–100 risk score from all enrichment results.

        Scoring:
          - AbuseIPDB confidence score contributes directly (max 50 pts)
          - VT malicious vote ratio contributes up to 50 pts
        """
        score = 0

        # AbuseIPDB contribution (take the worst IP)
        for r in report.ip_reputation:
            if r.found and not r.error:
                score = max(score, r.abuse_confidence_score // 2)   # 0–50 pts

        # VT contribution (IPs + URLs + hashes)
        all_vt = report.vt_ip_results + report.vt_url_results + report.vt_hash_results
        for r in all_vt:
            if r.found and r.total_engines > 0:
                ratio = r.malicious_votes / r.total_engines
                vt_pts = int(ratio * 50)                            # 0–50 pts
                score = max(score, score + vt_pts)

        score = min(score, 100)

        if score >= 70:
            label = "critical"
        elif score >= 40:
            label = "high"
        elif score >= 15:
            label = "medium"
        else:
            label = "low"

        return score, label

    @staticmethod
    def _make_note(report: EnrichmentReport) -> str:
        """Generate a one-paragraph human-readable summary for the analyst."""
        parts: list[str] = []

        # IP reputation summary
        for r in report.ip_reputation:
            if r.found and r.is_public:
                parts.append(
                    f"IP {r.ip}: AbuseIPDB confidence {r.abuse_confidence_score}% "
                    f"({r.total_reports} reports, {r.country_code}, {r.isp})"
                )

        # VT malicious hits
        for r in report.vt_ip_results + report.vt_url_results + report.vt_hash_results:
            if r.found and r.malicious_votes > 0:
                parts.append(
                    f"{r.ioc_type.upper()} {r.ioc}: {r.detection_ratio} engines flagged malicious"
                )

        if not parts:
            return "No threat intelligence signals found for extracted IOCs."

        return " | ".join(parts)
