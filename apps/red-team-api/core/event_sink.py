"""core/event_sink.py — fire-and-forget event publisher for the control API.

Posts a canonical `malicious_action_executed` event to the ATTENSE
control-API event-ingestion endpoint after each attack module run.
The module-level `requests` reference is left as an attribute so unit
tests can monkeypatch it without touching the real HTTP stack.
"""
from __future__ import annotations

import os
import uuid

import requests

_CONTROL_URL = os.getenv("ATTENSE_CONTROL_URL", "http://attense-app:8020")


def post_malicious_action_event(
    *,
    event_id: str,
    incident_id: str,
    scenario_id: str,
    actor_id: str,
    target_id: str,
    outcome: str,
    timestamp: str,
    metadata: dict,
    run_id: str,
) -> None:
    """POST one malicious_action_executed event to the control API.

    Uses ``result.started_at`` as the timestamp (the TTD anchor) so the
    blue team's detection time is measured from attack *start*, not the
    moment the module finished — a long-running scan must not inflate TTD.
    """
    secret = os.getenv("RED_TEAM_EVENTS_SECRET", "")
    url = f"{_CONTROL_URL}/api/incidents/events"
    payload = {
        "source": "red-team",
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "source_event_id": event_id,
        "run_id": run_id,
        "event_type": "malicious_action_executed",
        "timestamp": timestamp,
        "occurred_at": timestamp,
        "incident_id": incident_id,
        "scenario_id": scenario_id,
        "actor_id": actor_id,
        "actor_type": "red_team",
        "target_id": target_id,
        "outcome": outcome,
        "metadata": metadata or {},
    }
    requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Bearer {secret}"},
        timeout=10,
    ).raise_for_status()
