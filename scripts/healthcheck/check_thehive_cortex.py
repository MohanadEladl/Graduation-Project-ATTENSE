#!/usr/bin/env python3
"""Healthcheck for TheHive plus its Cortex connector."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


THEHIVE_STATUS_URL = "http://localhost:9000/api/status"


def main() -> int:
    try:
        with urllib.request.urlopen(THEHIVE_STATUS_URL, timeout=5) as response:
            status = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"TheHive status check failed: {exc}")
        return 1

    cortex = status.get("connectors", {}).get("cortex", {})
    connector_status = cortex.get("status")
    servers = cortex.get("servers", [])
    server_problems = [
        f"{server.get('name', 'cortex')}={server.get('status', 'UNKNOWN')}"
        for server in servers
        if server.get("status") != "OK"
    ]

    if connector_status != "OK" or server_problems:
        details = ", ".join(server_problems) if server_problems else "no server details"
        print(f"TheHive Cortex connector is not healthy: {connector_status}; {details}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
