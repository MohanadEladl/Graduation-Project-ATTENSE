"""
core/event_sink.py — Shared malicious_action_executed POST helper.

Both core/engine.py (scripted modules) and backend/zap_bridge.py (freestyle
ZAP-alert events) need to tell attense-app's incident pipeline that a
red-team action happened. This is that one shared POST, kept in core/ (not
backend/) because the standalone CLI in red-team/main.py uses core/engine.py
directly with no dependency on backend/ — core/ must stay backend-independent.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger("red-team.event_sink")

ATTENSE_APP_URL = os.environ.get("ATTENSE_APP_URL", "http://attense-app:8020")
EVENTS_ENDPOINT = f"{ATTENSE_APP_URL}/api/incidents/events"
EVENTS_SECRET = os.environ.get("RED_TEAM_EVENTS_SECRET", "")
EVENTS_TIMEOUT = float(os.environ.get("ATTENSE_EVENTS_TIMEOUT", "3"))


def post_malicious_action_event(
    *,
    event_id: str,
    incident_id: str,
    scenario_id: str,
    actor_id: str,
    target_id: str,
    outcome: str,
    timestamp: str,
    metadata: dict[str, Any],
    run_id: Optional[str] = None,
    source_event_id: Optional[str] = None,
    actor_type: str = "red_team",
    target_type: str = "service",
    event_type: str = "malicious_action_executed",
    log_fn: Optional[Callable[[str], None]] = None,
) -> None:
    """Fire-and-forget POST to attense-app's incident pipeline. Never raises
    and never blocks the caller on a slow/unreachable attense-app."""
    warn = log_fn or logger.warning

    # Canonical StandardEvent payload (report Phase 2). `timestamp` is still
    # accepted by the ingest endpoint as an alias for `occurred_at`; it is
    # produced UTC-aware upstream (engine.py uses datetime.now(timezone.utc)).
    # `source`/`schema_version` mark this producer as contract-compliant;
    # room_id/run_id correlation is threaded in a later phase.
    event = {
        "schema_version": "1.0",
        "source": "red-team",
        "event_id": event_id,
        "incident_id": incident_id,
        "run_id": run_id,
        "source_event_id": source_event_id,
        "scenario_id": scenario_id,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "target_id": target_id,
        "target_type": target_type,
        "event_type": event_type,
        "timestamp": timestamp,
        "outcome": outcome,
        "metadata": metadata,
    }

    try:
        resp = requests.post(
            EVENTS_ENDPOINT,
            json=event,
            headers={"Authorization": f"Bearer {EVENTS_SECRET}"},
            timeout=EVENTS_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        warn(f"Could not deliver {event_type} event to {EVENTS_ENDPOINT}: {exc}")
