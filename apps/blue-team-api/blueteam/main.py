"""
main.py - Blue Team Service Entry Point
========================================
Starts the FastAPI application for the Blue Team simulation.
"""

import logging
import threading
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Local imports
from .api.router import router as blueteam_router
from .api.webhook_router import webhook_router as hive_webhook_router
from .api.analyst_actions import router as analyst_actions_router
from .api.middleware import RequestLoggingMiddleware, TimingMiddleware
from .api.dependencies import get_attacker_log_attacher
from .infrastructure.eventstore.event_emitter import CrossRoomAccessError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

# How often the background poller retries cases with no attacker evidence
# yet (see AttackerLogAttacher.retry_pending).
_ATTACHER_POLL_INTERVAL_SECONDS = 20


def _attacher_poll_loop(stop_event: threading.Event) -> None:
    """Background loop retrying AttackerLogAttacher.retry_pending().

    Runs in a plain thread rather than an asyncio task: HiveClient and
    LabEvidenceConnector both make blocking httpx calls, so an asyncio task
    running this would stall the event loop for every other request.
    """
    attacher = get_attacker_log_attacher()
    while not stop_event.wait(_ATTACHER_POLL_INTERVAL_SECONDS):
        try:
            attacher.retry_pending()
        except Exception:
            logger.exception("[AttackerLogAttacher poll] retry_pending() failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    stop_event = threading.Event()
    poll_thread = threading.Thread(
        target=_attacher_poll_loop,
        args=(stop_event,),
        name="attacker-log-attacher-poll",
        daemon=True,
    )
    poll_thread.start()
    yield
    stop_event.set()
    poll_thread.join(timeout=5)


app = FastAPI(
    title="Attense Blue Team Service",
    description="REST interface for the Blue Team simulation layer.",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(TimingMiddleware)
app.add_middleware(RequestLoggingMiddleware)

# Routers
app.include_router(blueteam_router)
app.include_router(hive_webhook_router) # internal: Hive -> ATTENSE webhook receiver
app.include_router(analyst_actions_router) # Watcher Agent + Hive analyst-action ingestion


@app.exception_handler(CrossRoomAccessError)
async def _cross_room_access_handler(request: Request, exc: CrossRoomAccessError):
    """A cross-room access attempt is a tenant-isolation violation -> 403."""
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health", tags=["Info"])
def health():
    """Health check endpoint."""
    return {"status": "ok"}
