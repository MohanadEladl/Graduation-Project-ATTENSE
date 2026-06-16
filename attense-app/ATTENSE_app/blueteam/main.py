"""
main.py — Blue Team Service Entry Point
========================================
Starts the FastAPI application for the Blue Team simulation.
"""

import sys
import os
import logging

# Ensure the blueteam package root is in sys.path
_BLUETEAM_PATH = os.path.dirname(__file__)
if _BLUETEAM_PATH not in sys.path:
    sys.path.insert(0, _BLUETEAM_PATH)

# FastAPI imports
from fastapi import FastAPI

# Local imports
from api.router import router as blueteam_router
from api.webhook_router import webhook_router as hive_webhook_router
from api.middleware import RequestLoggingMiddleware, TimingMiddleware
from routers.analyst_actions import router as analyst_actions_router

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
app.include_router(analyst_actions_router)  # Watcher Agent + Hive analyst-action scoring

@app.get("/health", tags=["Info"])
def health():
    """Health check endpoint."""
    return {"status": "ok"}
