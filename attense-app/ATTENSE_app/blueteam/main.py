"""
main.py — Blue Team Service Entry Point
========================================
Starts the FastAPI application for the Blue Team simulation.
"""

import logging

# FastAPI imports
from fastapi import FastAPI

# Local imports
from .api.router import router as blueteam_router
from .api.webhook_router import webhook_router as hive_webhook_router
from .api.middleware import RequestLoggingMiddleware, TimingMiddleware

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

@app.get("/health", tags=["Info"])
def health():
    """Health check endpoint."""
    return {"status": "ok"}
