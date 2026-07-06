"""
main.py - FastAPI application and background alert-processing loop.

Endpoints
---------
GET /health - liveness probe
GET /events - last N events from the in-memory ring buffer
POST /events - manually inject a raw Wazuh alert JSON (for testing)
POST /ingest - alias for POST /events

The background daemon thread tails alerts.json and dispatches mapped events
through the configured output (file or HTTP).
"""
from __future__ import annotations

import os
import json
import hmac
import logging
import threading
import time
from collections import deque
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from app.config import settings
from app.mapper import map_alert
from app.output import dispatch, post_alert_body, raise_alert_body, set_active_room
from app.reader import tail_alerts

# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
)
logger = logging.getLogger("signal-mapper")

# -- FastAPI app ---------------------------------------------------------------
app = FastAPI(
    title="ATTENSE Signal Mapper",
    description=(
        "Ingests raw Wazuh alerts and converts them to ATTENSE StandardEvents. "
        "Supports file tail ingestion and HTTP/file output modes."
    ),
    version="2.0.0",
)

# -- In-memory ring buffer & Event Store ---------------------------------------
_MAX_RING = 500
_ring: deque[dict[str, Any]] = deque(maxlen=_MAX_RING)
_ring_lock = threading.Lock()

# Merged Event Store global state
_events: list[dict[str, Any]] = []
worker_task = None

# One Wazuh manager and one signal-store process serve the active exercise.
# This value is changed by the control API when a room starts/stops, rather
# than relying on the immutable INCIDENT_ID process environment variable.
_active_incident_id: str | None = None
_incident_lock = threading.Lock()


class ActiveIncidentRequest(BaseModel):
    incident_id: str | None = Field(default=None, min_length=1, max_length=200)
    # The room that owns this incident's alerts. Forwarded as X-Room-Id on every
    # raise-alert call so the Blue Team API accepts them (roomless calls 401).
    room_id: str | None = Field(default=None, min_length=1, max_length=200)


class ReplayRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=200)
    room_id: str = Field(min_length=1, max_length=200)
    # Only replay detections at/after this ISO timestamp (the room's attack
    # start), so events persisted from earlier exercises stay out of the room.
    since: str | None = Field(default=None, max_length=64)
    # Re-deliver every matching detection even if it was already replayed to this
    # room in this process. Used when a room is (re-)opened: an earlier delivery
    # may have silently failed (e.g. TheHive rejected it and the Blue Team API
    # swallowed the error), and the in-process dedup would otherwise never retry.
    # Safe to repeat: TheHive dedups alerts by sourceRef, so no duplicates appear.
    force: bool = Field(default=False)


# Detections already replayed to a room in this process, so a room re-entry
# doesn't re-post the whole store. TheHive's (type, source, sourceRef) dedup
# covers the process-restart case.
_replayed_refs: set[tuple[str, str]] = set()
_replayed_lock = threading.Lock()


def _get_active_incident_id() -> str | None:
    with _incident_lock:
        return _active_incident_id


def _set_active_incident_id(incident_id: str | None) -> None:
    global _active_incident_id
    with _incident_lock:
        _active_incident_id = incident_id


# -- Processing logic ----------------------------------------------------------

def _process_alert(raw: dict) -> None:
    event = map_alert(raw, incident_id_override=_get_active_incident_id())
    if event is None:
        return

    dispatch(event)

    ev_dict = event.to_dict()
    with _ring_lock:
        _ring.append(ev_dict)
        _events.append(ev_dict) # Keep in Event Store list

    logger.info(
        "[main] %-22s %-8s rule=%-6s src=%-15s outcome=%s",
        event.event_type,
        event.severity if hasattr(event, 'severity') else event.metadata.get('severity', 'unknown'),
        event.metadata.get("wazuh_rule_id") or "-",
        event.metadata.get("source_ip") or "-",
        event.outcome,
    )


def _tail_worker() -> None:
    """Daemon thread: tails alerts.json and dispatches events.

    Loops with backoff on any error so the worker never exits permanently.
    The /health endpoint reflects whether this thread is actually alive.
    """
    logger.info("[main] Alert tailing worker started.")
    while True:
        try:
            for raw in tail_alerts():
                _process_alert(raw)
            # tail_alerts() is an infinite generator; returning means something
            # terminated it unexpectedly. Restart immediately.
            logger.warning("[main] tail_alerts() generator ended unexpectedly - restarting.")
        except Exception as exc:
            logger.error(
                "[main] Tail worker error: %s - restarting in 5s.", exc, exc_info=True
            )
            time.sleep(5)


# -- Lifecycle -----------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    global worker_task
    logger.info(
        "[main] Signal Store (Merged Mapper + Event Store) starting. "
        "alerts_path=%s output_mode=%s",
        settings.wazuh_alerts_path,
        settings.output_mode,
    )
    
    # Load initial events from file if it exists (Optional persistent store)
    output_path = os.getenv("OUTPUT_PATH", "/attense/data/mapped_events.jsonl")
    if os.path.exists(output_path):
        try:
            count = 0
            with open(output_path, "r") as f:
                for line in f:
                    if line.strip():
                        # Use a temporary name for counting if _events is empty or similar
                        _events.append(json.loads(line))
                        count += 1
            logger.info(f"Loaded {count} events from {output_path}")
        except Exception as e:
            logger.error(f"Failed to load events: {e}")

    # Start the daemon thread worker for tailing
    t = threading.Thread(target=_tail_worker, daemon=True, name="tail-worker")
    t.start()
    worker_task = t # Store thread reference for health check


# -- Endpoints -----------------------------------------------------------------

@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health() -> JSONResponse:
    alive = worker_task is not None and worker_task.is_alive()
    return JSONResponse(
        status_code=200 if alive else 503,
        content={
            "status": "ok" if alive else "degraded",
            "output_mode": settings.output_mode,
            "events_buffered": len(_ring),
            "worker_running": alive,
            "events_in_store": len(_events),
            "active_incident_id": _get_active_incident_id(),
        },
    )


@app.put("/configuration/active-incident", tags=["ops"])
async def configure_active_incident(
    body: ActiveIncidentRequest,
    x_signal_store_secret: str | None = Header(default=None),
) -> dict[str, str | None]:
    """Set or clear the incident used for subsequently mapped Wazuh alerts.

    This endpoint is internal-only and authenticated. Clearing the context on
    room close makes the configured fallback INCIDENT_ID available again for
    standalone exercises.
    """
    _require_config_secret(x_signal_store_secret)

    _set_active_incident_id(body.incident_id)
    set_active_room(body.room_id)
    logger.info(
        "[main] Active exercise incident changed to %s (room=%s)",
        body.incident_id or "<fallback>", body.room_id or "<none>",
    )
    return {"active_incident_id": body.incident_id, "active_room_id": body.room_id}


def _require_config_secret(provided: str | None) -> None:
    expected = settings.signal_store_config_secret
    if not expected:
        raise HTTPException(status_code=503, detail="Runtime incident configuration is disabled")
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid signal-store configuration secret")


def _at_or_after(timestamp: str | None, since: str) -> bool:
    """True when *timestamp* is at/after *since*. Unparseable values pass
    through (better a stray alert in the room than a silently empty case)."""
    from datetime import datetime, timezone

    try:
        ts = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        floor = datetime.fromisoformat(str(since).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if floor.tzinfo is None:
        floor = floor.replace(tzinfo=timezone.utc)
    return ts >= floor


@app.post("/replay", tags=["ops"], summary="Replay stored detections into a room")
async def replay_detections(
    body: ReplayRequest,
    x_signal_store_secret: str | None = Header(default=None),
) -> dict[str, int]:
    """Re-deliver stored attack detections to the Blue Team API for a room.

    In deferred exercises the attack (and its Wazuh detections) happens before
    any analyst enters the room, and roomless raise-alert calls are rejected -
    so those alerts never reached TheHive. The control API calls this when a
    Blue Team user enters the room: every stored detection belonging to the
    room's incident (or mapped under the static fallback incident before the
    room claimed the signal-store) is re-posted with the room's X-Room-Id,
    landing the case's alerts in TheHive while the analyst is inside it.
    """
    _require_config_secret(x_signal_store_secret)

    fallback_incident = os.getenv("INCIDENT_ID")
    with _ring_lock:
        candidates = list(_events)

    replayed = skipped = failed = 0
    for ev in candidates:
        if ev.get("outcome") != "detected":
            continue
        ev_incident = ev.get("incident_id")
        # Own the event if it was mapped for this incident, or if it predates
        # the room claiming the signal-store (fallback / self-minted ids).
        unclaimed = ev_incident == fallback_incident or str(ev_incident or "").startswith("wazuh-")
        if ev_incident != body.incident_id and not unclaimed:
            continue
        if body.since and not _at_or_after(ev.get("timestamp"), body.since):
            continue
        ref = (body.room_id, str(ev.get("event_id") or id(ev)))
        # force re-delivers even if already replayed - heals a room whose earlier
        # delivery silently failed. TheHive dedups by sourceRef, so no duplicates.
        if not body.force:
            with _replayed_lock:
                if ref in _replayed_refs:
                    skipped += 1
                    continue
        if post_alert_body(raise_alert_body(ev, incident_id=body.incident_id), body.room_id):
            replayed += 1
            with _replayed_lock:
                _replayed_refs.add(ref)
        else:
            failed += 1

    logger.info(
        "[main] Replay for room=%s incident=%s: %d replayed, %d skipped, %d failed",
        body.room_id, body.incident_id, replayed, skipped, failed,
    )
    return {"replayed": replayed, "skipped": skipped, "failed": failed}


@app.get("/events", tags=["events"], summary="Return last N mapped events")
async def list_events(limit: int = 50) -> list[dict]:
    """Return the last *limit* mapped StandardEvents from the ring buffer."""
    limit = max(1, min(limit, _MAX_RING))
    with _ring_lock:
        return list(_ring)[-limit:]


@app.post("/events", tags=["events"], status_code=202,
          summary="Manually inject a raw Wazuh alert")
@app.post("/ingest", tags=["events"], status_code=202, include_in_schema=False)
async def ingest_alert(request: Request) -> JSONResponse:
    """
    Inject a raw Wazuh alert dict for immediate processing.
    Returns the mapped StandardEvent (202 Accepted).
    """
    try:
        raw: dict = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event = map_alert(raw, incident_id_override=_get_active_incident_id())
    if event is None:
        raise HTTPException(
            status_code=422, detail="Could not map alert to ATTENSE StandardEvent"
        )

    dispatch(event)
    with _ring_lock:
        _ring.append(event.to_dict())

    return JSONResponse(content=event.to_dict(), status_code=202)


# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=False,
    )
