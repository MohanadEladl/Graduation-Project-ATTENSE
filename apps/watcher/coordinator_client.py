"""
coordinator_client.py — Watcher Agent coordinator poller.

Polls the Red Team backend until the session code resolves to an active
watcher session, then returns the session details.
"""

from __future__ import annotations

import time

import requests


def wait_for_session(
    coordinator_url: str,
    session_code: str,
    poll_interval: int = 5,
) -> tuple[str, str, float]:
    """
    Poll GET {coordinator_url}/session/watcher/{session_code} every
    *poll_interval* seconds until status == "active".

    Returns
    -------
    (incident_id, scenario_id, started_at_unix)
    """
    url = f"{coordinator_url.rstrip('/')}/session/watcher/{session_code}"
    print("Standby — waiting for session...")

    while True:
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "active":
                print(f"Session active — incident={data['incident_id']}  scenario={data['scenario_id']}")
                return (
                    data["incident_id"],
                    data["scenario_id"],
                    float(data["started_at_unix"]),
                )
        except requests.RequestException as exc:
            print(f"[coordinator] poll error: {exc}")

        time.sleep(poll_interval)
