"""
signal_mapper_nginx.py  –  Signal Mapper entry-point for Nginx sandbox integration.

This replaces the standard main.py entry-point ONLY for the sandbox setup.
It swaps out the Wazuh file reader for a plain nginx access log tail,
converts each line via NginxLogAdapter, then feeds the result into the
existing map_alert() → dispatch() pipeline UNCHANGED.

WHY A SEPARATE ENTRY-POINT?
────────────────────────────
The standard reader.py expects each input line to be a Wazuh JSON alert.
Nginx writes plain Combined Log Format text instead.
Rather than modifying the core reader.py (which would break the Wazuh path),
this thin entry-point wraps the adapter and reuses everything else as-is.

ENV VARS consumed (same as main.py, plus two extras):
  WAZUH_ALERTS_PATH   – path to nginx access.log (mounted volume)
  OUTPUT_MODE         – "file" or "http"
  OUTPUT_PATH         – JSONL output file (used when OUTPUT_MODE=file)
  EVENT_STORE_URL     – event-store-mock URL (used when OUTPUT_MODE=http)
  FILE_WAIT_TIMEOUT   – seconds to wait for the log file before giving up
  POLL_INTERVAL       – polling interval in seconds when no new lines
  SCENARIO_ID         – injected into every event's scenario_id field
  INCIDENT_ID         – injected into every event's incident_id field
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# ── Import the existing pipeline unchanged ───────────────────────────────────
from app.config import settings
from app.mapper import map_alert
from app.output import dispatch

# ── Import the nginx adapter (lives alongside this file in the image) ─────────
from nginx_adapter import NginxLogAdapter

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
)
logger = logging.getLogger("signal-mapper-nginx")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ATTENSE Signal Mapper (Nginx mode)",
    description=(
        "Tails Nginx access.log, adapts each line to a Wazuh-shaped alert dict, "
        "then maps it to an ATTENSE StandardEvent using the standard pipeline."
    ),
    version="2.0.0-nginx",
)

# ── In-memory ring buffer (same as main.py) ───────────────────────────────────
_MAX_RING = 500
_ring: deque[dict[str, Any]] = deque(maxlen=_MAX_RING)
_ring_lock = threading.Lock()

# ── Adapter instance ──────────────────────────────────────────────────────────
_adapter = NginxLogAdapter(
    agent_name="sandbox-target",
    agent_id="001",
)

# ── Optional scenario/incident context override from env ──────────────────────
_SCENARIO_ID = os.environ.get("SCENARIO_ID", "phase2-nginx-traffic")
_INCIDENT_ID = os.environ.get("INCIDENT_ID", "phase2-incident-001")


# ── Core processing ───────────────────────────────────────────────────────────

def _process_line(raw_line: str) -> None:
    """Parse one nginx log line → StandardEvent → dispatch."""
    alert_dict = _adapter.parse(raw_line)
    if alert_dict is None:
        return

    event = map_alert(alert_dict)
    if event is None:
        return

    # Inject scenario / incident context
    event.scenario_id = _SCENARIO_ID
    event.incident_id = _INCIDENT_ID

    dispatch(event)

    with _ring_lock:
        _ring.append(event.to_dict())

    logger.info(
        "[main] %-22s %-8s  rule=%-6s  src=%-15s  outcome=%s",
        event.event_type,
        event.metadata.get("severity", "unknown"),
        event.metadata.get("wazuh_rule_id") or "–",
        event.metadata.get("source_ip") or "–",
        event.outcome,
    )


def _tail_nginx_log() -> None:
    """
    Daemon thread: wait for the nginx access.log to appear, then tail it
    forever, processing each new line through the pipeline.
    """
    path = settings.wazuh_alerts_path  # repurposed env var → nginx log path
    timeout = settings.file_wait_timeout
    poll = settings.poll_interval

    # Wait for the log file (nginx may take a moment to create it)
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            logger.critical("[tail] Timed out waiting for nginx log: %s", path)
            return
        logger.info("[tail] Waiting for nginx log: %s", path)
        time.sleep(1)

    logger.info("[tail] Nginx log found: %s  —  following new lines.", path)

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        # Skip existing content (we only care about new requests)
        for _ in fh:
            pass
        logger.info("[tail] Skipped existing log content.")

        while True:
            line = fh.readline()
            if not line:
                time.sleep(poll)
                continue
            _process_line(line)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    logger.info(
        "[main] Signal Mapper (Nginx mode) starting.  "
        "log_path=%s  output_mode=%s  scenario=%s",
        settings.wazuh_alerts_path,
        settings.output_mode,
        _SCENARIO_ID,
    )
    t = threading.Thread(target=_tail_nginx_log, daemon=True, name="nginx-tail")
    t.start()


# ── Endpoints (same surface area as main.py) ──────────────────────────────────

@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {
        "status": "ok",
        "mode": "nginx",
        "output_mode": settings.output_mode,
        "log_path": settings.wazuh_alerts_path,
        "events_buffered": len(_ring),
        "scenario_id": _SCENARIO_ID,
        "incident_id": _INCIDENT_ID,
    }


@app.get("/events", tags=["events"])
async def list_events(limit: int = 50) -> list[dict]:
    """Return the last *limit* StandardEvents from the in-memory buffer."""
    limit = max(1, min(limit, _MAX_RING))
    with _ring_lock:
        return list(_ring)[-limit:]


@app.post("/events", tags=["events"], status_code=202)
@app.post("/ingest", tags=["events"], status_code=202, include_in_schema=False)
async def ingest_line(request: Request) -> JSONResponse:
    """
    Manually inject a raw nginx log line (plain text) or a Wazuh alert dict (JSON).
    Useful for testing without live traffic.
    """
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        # Accept a pre-formed Wazuh-shaped dict (for compatibility with test suite)
        try:
            raw: dict = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        event = map_alert(raw)
    else:
        # Accept a plain nginx log line
        body_bytes = await request.body()
        raw_line = body_bytes.decode("utf-8", errors="replace")
        alert_dict = _adapter.parse(raw_line)
        if alert_dict is None:
            raise HTTPException(status_code=422, detail="Could not parse nginx log line")
        event = map_alert(alert_dict)

    if event is None:
        raise HTTPException(status_code=422, detail="Could not map to ATTENSE StandardEvent")

    event.scenario_id = _SCENARIO_ID
    event.incident_id = _INCIDENT_ID
    dispatch(event)
    with _ring_lock:
        _ring.append(event.to_dict())

    return JSONResponse(content=event.to_dict(), status_code=202)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "signal_mapper_nginx:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=False,
    )
