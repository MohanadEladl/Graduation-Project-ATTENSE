"""
classifier.py – Map Wazuh alert metadata to ATTENSE event_type and severity.

Covers ONLY the 6 application-based attack scenarios defined in scenarios.json:
  APP-01: Cross-Site Scripting (XSS)
  APP-02: Command Injection
  APP-03: Directory Traversal
  APP-04: File Upload Exploit
  APP-05: Cross-Site Request Forgery (CSRF)
  APP-06: Broken Authentication

Classification priority (highest → lowest):
  1. Exact rule-ID lookup
  2. Rule-group keyword match
  3. Description / full_log keyword match
  4. Rule-level numeric threshold (severity only; event_type → "generic")
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from app.schema import WazuhAlert


SeverityT = Literal["low", "medium", "high", "critical"]
OutcomeT  = Literal["detected", "blocked", "allowed", "unknown"]


@dataclass(frozen=True)
class Classification:
    event_type: str
    severity:   SeverityT
    outcome:    OutcomeT = "detected"


# ── Rule-ID exact match ───────────────────────────────────────────────────────
# Wazuh web attack rule IDs mapped to our APP scenarios

_RULE_ID_MAP: dict[str, Classification] = {

    # APP-01: XSS – Wazuh web rules for script injection
    "31106": Classification("xss",                  "high",     "detected"),
    "31108": Classification("xss",                  "high",     "detected"),
    "31109": Classification("xss",                  "critical", "detected"),

    # APP-02: Command Injection – Wazuh web rules for OS command injection
    "31120": Classification("command_injection",    "critical", "detected"),
    "31121": Classification("command_injection",    "high",     "detected"),

    # APP-03: Directory Traversal – Wazuh web rules for path traversal
    "31140": Classification("directory_traversal",  "high",     "detected"),
    "31141": Classification("directory_traversal",  "critical", "detected"),

    # APP-04: File Upload Exploit – Wazuh web rules for malicious uploads
    "31160": Classification("file_upload_exploit",  "critical", "detected"),
    "31161": Classification("file_upload_exploit",  "high",     "detected"),
    # ATTENSE local rule for executable extension uploads (.php/.sh/.jsp...)
    "100150": Classification("file_upload_exploit", "critical", "detected"),

    # APP-05: CSRF – anomalous authenticated request patterns
    "31170": Classification("csrf",                 "high",     "detected"),
    "31171": Classification("csrf",                 "critical", "detected"),

    # APP-06: Broken Authentication – login brute force / credential stuffing
    "31151": Classification("broken_authentication","critical", "detected"),
    "31100": Classification("broken_authentication","high",     "detected"),
    "31101": Classification("broken_authentication","high",     "detected"),
    "5710":  Classification("broken_authentication","low",      "detected"),
    "5711":  Classification("broken_authentication","medium",   "detected"),
    "5712":  Classification("broken_authentication","high",     "detected"),
    "2503":  Classification("broken_authentication","critical", "detected"),
}


# ── Rule-group keyword match ──────────────────────────────────────────────────

_GROUP_MAP: list[tuple[str, Classification]] = [
    # APP-01: XSS
    ("xss",                   Classification("xss",                  "high",     "detected")),

    # APP-02: Command injection
    ("command_injection",     Classification("command_injection",    "critical", "detected")),
    ("rce",                   Classification("command_injection",    "critical", "detected")),

    # APP-03: Directory traversal
    ("traversal",             Classification("directory_traversal",  "high",     "detected")),
    ("path_traversal",        Classification("directory_traversal",  "high",     "detected")),

    # APP-04: File upload
    ("file_upload",           Classification("file_upload_exploit",  "critical", "detected")),
    ("web_shell",             Classification("file_upload_exploit",  "critical", "detected")),

    # APP-05: CSRF
    ("csrf",                  Classification("csrf",                 "high",     "detected")),

    # APP-06: Broken authentication
    ("authentication_failed", Classification("broken_authentication","medium",   "detected")),
    ("sqli",                  Classification("broken_authentication","high",     "detected")),
    ("web",                   Classification("broken_authentication","medium",   "detected")),
]


# ── Description / full_log keyword match ─────────────────────────────────────

_KEYWORD_MAP: list[tuple[list[str], Classification]] = [
    # APP-01: XSS
    (
        ["<script", "javascript:", "onerror=", "onload=", "xss", "cross-site scripting"],
        Classification("xss",                  "high",     "detected"),
    ),
    # APP-02: Command Injection
    (
        ["cmd=", "exec=", "system(", "passthru(", "shell_exec", "command injection",
         "os command", ";ls", ";id", "|whoami"],
        Classification("command_injection",    "critical", "detected"),
    ),
    # APP-03: Directory Traversal
    (
        ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow",
         "directory traversal", "path traversal", "/proc/self"],
        Classification("directory_traversal",  "high",     "detected"),
    ),
    # APP-04: File Upload Exploit
    (
        ["file upload", "malicious file", ".php upload", ".jsp upload",
         "webshell", "backdoor upload", "multipart/form-data"],
        Classification("file_upload_exploit",  "critical", "detected"),
    ),
    # APP-05: CSRF
    (
        ["csrf", "cross-site request", "forged request", "unauthorized state change"],
        Classification("csrf",                 "high",     "detected"),
    ),
    # APP-06: Broken Authentication
    (
        ["failed login", "failed password", "authentication failure",
         "credential stuffing", "brute force", "invalid user",
         "union select", "sql injection", "login attempt"],
        Classification("broken_authentication","medium",   "detected"),
    ),
]


# ── Severity threshold (last resort) ─────────────────────────────────────────

def _level_to_severity(level: int) -> SeverityT:
    if level >= 11:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


# ── Public classifier ─────────────────────────────────────────────────────────

def classify(alert: WazuhAlert) -> Classification:
    """Return the best Classification for *alert*."""

    # 1 – Exact rule-ID match
    if alert.rule.id in _RULE_ID_MAP:
        return _RULE_ID_MAP[alert.rule.id]

    # 2 – Group keyword match
    groups_lower = [g.lower() for g in alert.rule.groups]
    for keyword, cls in _GROUP_MAP:
        if any(keyword in g for g in groups_lower):
            return cls

    # 3 – Description / full_log keyword match
    text = (alert.rule.description + " " + alert.full_log).lower()
    for keywords, cls in _KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            level_sev = _level_to_severity(alert.rule.level)
            _order = ["low", "medium", "high", "critical"]
            effective_sev: SeverityT = (
                level_sev
                if _order.index(level_sev) > _order.index(cls.severity)
                else cls.severity
            )
            return Classification(cls.event_type, effective_sev, cls.outcome)

    # 4 – Level threshold only → generic
    return Classification(
        event_type="generic",
        severity=_level_to_severity(alert.rule.level),
        outcome="detected",
    )