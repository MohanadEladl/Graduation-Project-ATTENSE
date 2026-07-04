"""
nginx_adapter.py  –  Nginx access log → Wazuh-shaped alert dict

PURPOSE
-------
The ATTENSE Signal Mapper (reader.py + mapper.py) expects each line in its
input file to be a JSON object that looks like a Wazuh alert:

    { "timestamp": "...", "rule": {...}, "agent": {...}, "data": {...}, ... }

The sandbox Nginx target writes plain-text Combined Log Format instead:

    172.18.0.1 - - [27/Feb/2026:17:00:00 +0000] "GET /path HTTP/1.1" 200 512 ...

This adapter sits between the two:

  nginx access.log  ──►  nginx_adapter.py  ──►  mapped_events.jsonl (Wazuh-shaped)

It is invoked by signal_mapper_nginx.py (the modified entry-point for the
sandbox integration) and produces synthetic Wazuh alert objects so that the
existing mapper.py / classifier.py / schema.py pipeline requires ZERO changes.

HOW IT PLUGS IN
---------------
The signal-mapper container is started with a modified main entry-point
(signal_mapper_nginx.py) that:
  1. Tails /nginx-logs/access.log line by line.
  2. Passes each line to NginxLogAdapter.parse().
  3. Feeds the resulting dict straight into the existing map_alert() pipeline.

SYNTHETIC WAZUH RULE IDs used here:
  31100 – web_attack  (GET/POST with suspicious patterns → mapped by classifier)
  31200 – http_access (normal HTTP request)
  31400 – http_error  (4xx client error)
  31500 – http_server_error (5xx server error)
All IDs >= 31100 match the web_attack group in classifier.py.
"""
from __future__ import annotations

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("signal-mapper.nginx_adapter")

# ── Nginx Combined Log Format regex ─────────────────────────────────────────
# Example:
#   172.18.0.1 - - [27/Feb/2026:17:00:01 +0000] "GET /index.html HTTP/1.1" 200 615 "-" "curl/8.0"
_COMBINED_RE = re.compile(
    r'(?P<remote_addr>\S+)'          # client IP
    r'\s+\S+'                        # ident (-)
    r'\s+\S+'                        # user (-)
    r'\s+\[(?P<time_local>[^\]]+)\]' # [timestamp]
    r'\s+"(?P<request>[^"]*)"'       # "METHOD /path HTTP/x.x"
    r'\s+(?P<status>\d{3})'          # status code
    r'\s+(?P<body_bytes>\d+|-)'      # bytes sent
    r'(?:\s+"(?P<referer>[^"]*)")?'  # optional referer
    r'(?:\s+"(?P<user_agent>[^"]*)")?'  # optional user-agent
)

# Nginx timestamp format: 27/Feb/2026:17:00:01 +0000
_NGINX_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# ── Attack pattern detection ─────────────────────────────────────────────────
# Patterns in the request URI / user-agent that trigger a "web_attack" rule
_ATTACK_PATTERNS = [
    r"(?i)(union\s+select|select\s+.*from|drop\s+table)",  # SQL injection
    r"(?i)(<script|javascript:|onerror=|onload=)",          # XSS
    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f)",                      # Directory traversal
    r"(?i)(/etc/passwd|/etc/shadow|/proc/self)",            # LFI
    r"(?i)(cmd=|exec=|system\(|passthru\()",                # Command injection
    r"(?i)(phpinfo\(\)|eval\(|base64_decode)",              # Code injection
]
_ATTACK_RE = re.compile("|".join(_ATTACK_PATTERNS))


def _parse_nginx_time(time_str: str) -> str:
    """Convert Nginx timestamp string to ISO-8601 UTC string."""
    try:
        dt = datetime.strptime(time_str.strip(), _NGINX_TS_FMT)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _classify_request(method: str, path: str, status: int, user_agent: str) -> tuple[str, int, list[str], str]:
    """
    Returns (description, rule_id, groups, full_log) based on request characteristics.

    Rule ID mapping (synthetic, compatible with classifier.py):
      31151 → web_attack critical  (attack pattern detected)
      31100 → web_attack high      (suspicious method or path)
      31400 → http_error medium    (4xx client error)
      31500 → http_server_error high (5xx server error)
      31200 → http_access low      (normal request)
    """
    request_text = f"{method} {path} {user_agent}"

    # 1. Attack patterns in URI or user-agent → highest priority
    if _ATTACK_RE.search(request_text):
        return (
            f"Web attack pattern detected: {method} {path}",
            31151,
            ["web", "attack", "sqli"] if "select" in path.lower() or "union" in path.lower()
            else ["web", "attack", "xss"] if "script" in path.lower()
            else ["web", "attack"],
            f'{method} {path} (status={status}) ua="{user_agent}"',
        )

    # 2. Suspicious HTTP methods
    if method in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
        return (
            f"Unusual HTTP method observed: {method} {path}",
            31100,
            ["web", "http_unusual_method"],
            f'{method} {path} (status={status})',
        )

    # 3. 5xx – server errors
    if 500 <= status < 600:
        return (
            f"HTTP {status} server error on {path}",
            31500,
            ["web", "http_error"],
            f'{method} {path} → {status}',
        )

    # 4. 4xx – client errors (may indicate scanning / probing)
    if 400 <= status < 500:
        return (
            f"HTTP {status} client error on {path}",
            31400,
            ["web", "http_error"] if status != 404 else ["web", "recon"],
            f'{method} {path} → {status}',
        )

    # 5. Normal request
    return (
        f"HTTP {status} {method} {path}",
        31200,
        ["web", "http_access"],
        f'{method} {path} (status={status})',
    )


class NginxLogAdapter:
    """
    Stateless adapter: one nginx access log line → one Wazuh-shaped alert dict.

    The output dict is compatible with WazuhAlert.from_dict() in schema.py,
    so the rest of the Signal Mapper pipeline requires no changes at all.
    """

    def __init__(self, agent_name: str = "sandbox-target", agent_id: str = "001"):
        self.agent_name = agent_name
        self.agent_id = agent_id

    def parse(self, line: str) -> Optional[dict]:
        """
        Parse one nginx access log line.

        Returns a Wazuh-compatible alert dict, or None if the line
        cannot be parsed (e.g. blank lines, startup messages).
        """
        line = line.strip()
        if not line:
            return None

        m = _COMBINED_RE.match(line)
        if not m:
            logger.debug("[nginx_adapter] Line did not match Combined Log Format: %.80s", line)
            return None

        remote_addr = m.group("remote_addr")
        time_local   = m.group("time_local")
        request      = m.group("request")
        status       = int(m.group("status") or 200)
        body_bytes   = m.group("body_bytes") or "0"
        user_agent   = m.group("user_agent") or ""

        # Parse "METHOD /path HTTP/x.x"
        req_parts = request.split(" ")
        method = req_parts[0] if len(req_parts) >= 1 else "GET"
        path   = req_parts[1] if len(req_parts) >= 2 else "/"

        description, rule_id, groups, full_log = _classify_request(
            method, path, status, user_agent
        )

        # ── Assemble the Wazuh-shaped dict ────────────────────────────────────
        # This mirrors the structure that WazuhAlert.from_dict() expects.
        alert = {
            "timestamp": _parse_nginx_time(time_local),
            "rule": {
                "id":          str(rule_id),
                "level":       _rule_level(rule_id),
                "description": description,
                "groups":      groups,
                "mitre":       None,
            },
            "agent": {
                "id":   self.agent_id,
                "name": self.agent_name,
                "ip":   "172.18.0.1",   # Nginx container IP in attense_net
            },
            "location": f"nginx:{path}",
            "full_log": full_log,
            "data": {
                "srcip": remote_addr,
                "dstip": "",
                "method":     method,
                "status_code": str(status),
                "url":         path,
                "bytes":       body_bytes,
                "user_agent":  user_agent,
            },
        }

        logger.debug(
            "[nginx_adapter] %s %s → rule=%s  status=%s  src=%s",
            method, path, rule_id, status, remote_addr,
        )
        return alert


def _rule_level(rule_id: int) -> int:
    """Map our synthetic rule IDs to Wazuh-style severity levels (0–15)."""
    return {
        31151: 12,   # critical web attack
        31100: 8,    # high – web attack / unusual method
        31500: 7,    # high – server error
        31400: 4,    # medium – client error / recon
        31200: 1,    # low – normal traffic
    }.get(rule_id, 3)
