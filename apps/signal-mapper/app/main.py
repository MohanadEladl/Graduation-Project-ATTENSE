"""
main.py – FastAPI application and background alert-processing loop.

Endpoints
---------
GET  /health   – liveness probe
GET  /events   – last N events from the in-memory ring buffer
POST /events   – manually inject a raw Wazuh alert JSON (for testing)
POST /ingest   – alias for POST /events

The background daemon thread tails alerts.json and dispatches mapped events
through the configured output (file or HTTP).
"""
from __future__ import annotations

import os
import json
import asyncio
import logging
import threading
import time
from collections import deque
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.mapper import map_alert
from app.output import dispatch
from app.reader import tail_alerts

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
)
logger = logging.getLogger("signal-mapper")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ATTENSE Signal Mapper",
    description=(
        "Ingests raw Wazuh alerts and converts them to ATTENSE StandardEvents. "
        "Supports file tail ingestion and HTTP/file output modes."
    ),
    version="2.0.0",
)

# ── In-memory ring buffer & Event Store ───────────────────────────────────────
_MAX_RING = 500
_ring: deque[dict[str, Any]] = deque(maxlen=_MAX_RING)
_ring_lock = threading.Lock()

# Merged Event Store global state
_events: list[dict[str, Any]] = []
worker_task = None


# ── Processing logic ──────────────────────────────────────────────────────────

def _process_alert(raw: dict) -> None:
    event = map_alert(raw)
    if event is None:
        return

    dispatch(event)

    ev_dict = event.to_dict()
    with _ring_lock:
        _ring.append(ev_dict)
        _events.append(ev_dict) # Keep in Event Store list

    logger.info(
        "[main] %-22s %-8s  rule=%-6s  src=%-15s  outcome=%s",
        event.event_type,
        event.severity if hasattr(event, 'severity') else event.metadata.get('severity', 'unknown'),
        event.metadata.get("wazuh_rule_id") or "–",
        event.metadata.get("source_ip") or "–",
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
            logger.warning("[main] tail_alerts() generator ended unexpectedly — restarting.")
        except Exception as exc:
            logger.error(
                "[main] Tail worker error: %s — restarting in 5s.", exc, exc_info=True
            )
            time.sleep(5)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    global worker_task
    logger.info(
        "[main] Signal Store (Merged Mapper + Event Store) starting.  "
        "alerts_path=%s  output_mode=%s",
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


# ── Endpoints ─────────────────────────────────────────────────────────────────

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
        },
    )


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

    event = map_alert(raw)
    if event is None:
        raise HTTPException(
            status_code=422, detail="Could not map alert to ATTENSE StandardEvent"
        )

    dispatch(event)
    with _ring_lock:
        _ring.append(event.to_dict())

    return JSONResponse(content=event.to_dict(), status_code=202)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=False,
    )
