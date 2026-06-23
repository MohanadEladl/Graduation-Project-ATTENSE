"""
main.py — Blue Team Service Entry Point
========================================
Starts the FastAPI application for the Blue Team simulation.
"""

import logging

# FastAPI imports
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Local imports
from .api.router import router as blueteam_router
from .api.webhook_router import webhook_router as hive_webhook_router
from .api.analyst_actions import router as analyst_actions_router
from .api.middleware import RequestLoggingMiddleware, TimingMiddleware
from .infrastructure.eventstore.event_emitter import CrossRoomAccessError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="Attense Blue Team Service",
    description="REST interface for the Blue Team simulation layer.",
    version="1.0.0",
)

# Middleware
app.add_middleware(TimingMiddleware)
app.add_middleware(RequestLoggingMiddleware)

# Routers
app.include_router(blueteam_router)
app.include_router(hive_webhook_router)  # internal: Hive → ATTENSE webhook receiver
app.include_router(analyst_actions_router)  # Watcher Agent + Hive analyst-action ingestion


@app.exception_handler(CrossRoomAccessError)
async def _cross_room_access_handler(request: Request, exc: CrossRoomAccessError):
    """A cross-room access attempt is a tenant-isolation violation → 403."""
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health", tags=["Info"])
def health():
    """Health check endpoint."""
    return {"status": "ok"}
