"""
middleware.py — Blue Team API Middleware
=========================================
Cross-cutting concerns that run automatically BEFORE or AFTER
every request reaches a route handler.

Every request passes through this checkpoint:
    auth → permissions → logging → timing → request
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("blueteam.middleware")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log every incoming request and its response status/latency.

    Attaches a unique request_id to each request so it can be
    traced across logs.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        logger.info(
            "[%s] → %s %s",
            request_id,
            request.method,
            request.url.path,
        )

        response = await call_next(request)

        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "[%s] ← %s  (%.1f ms)",
            request_id,
            response.status_code,
            elapsed_ms,
        )

        # Attach trace id to response headers for debugging
        response.headers["X-Request-ID"] = request_id
        return response


class TimingMiddleware(BaseHTTPMiddleware):
    """
    Add X-Process-Time header to every response.
    Useful for performance monitoring.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        response.headers["X-Process-Time"] = f"{elapsed:.4f}s"
        return response
