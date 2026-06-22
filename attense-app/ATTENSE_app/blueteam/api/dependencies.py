"""
dependencies.py — Dependency Injection for Blue Team API
=========================================================
Provides shared dependencies that are injected into route handlers
via FastAPI's Depends() mechanism.

Instead of creating services inside every route, components are
supplied from outside (the military supplies the rifle, not the soldier).

Injected dependencies:
    - EventStore  : in-memory event log (swap for DB/Kafka in production)
    - HiveClient  : TheHive integration (stubbed until Hive is live)
    - SandboxConnector : controls the target sandbox environment
    - Logger      : audit-trail logger
    - Settings    : runtime config
"""

from __future__ import annotations

import logging
from functools import lru_cache

from infrastructure.eventstore.event_emitter import EventEmitter
from infrastructure.thehive.hive_client import HiveClient
from infrastructure.sandbox.target_connector import TargetConnector
from infrastructure.cortex.enrichment_service import EnrichmentService
from config.settings import Settings


# ─────────────────────────────────────────────────────────────────────────────
# Settings singleton
# ─────────────────────────────────────────────────────────────────────────────

@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (reads env vars once)."""
    return Settings()


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure singletons
# ─────────────────────────────────────────────────────────────────────────────

# Single shared EventEmitter — all routes publish through the same store.
_event_emitter = EventEmitter()


def get_event_emitter() -> EventEmitter:
    """Provide the shared EventEmitter (event store wrapper)."""
    return _event_emitter


def get_hive_client() -> HiveClient:
    """Provide a HiveClient instance for case management."""
    settings = get_settings()
    return HiveClient(base_url=settings.hive_url, api_key=settings.hive_api_key)


def get_sandbox_connector() -> TargetConnector:
    """Provide a TargetConnector for sandbox / host isolation."""
    settings = get_settings()
    return TargetConnector(base_url=settings.sandbox_url)


def get_enrichment_service() -> EnrichmentService:
    """Provide a Cortex-Lite EnrichmentService for IOC threat intelligence."""
    settings = get_settings()
    return EnrichmentService(
        vt_api_key=settings.virustotal_api_key,
        abuse_api_key=settings.abuseipdb_api_key,
    )


def get_logger() -> logging.Logger:
    """Provide the Blue Team audit logger."""
    return logging.getLogger("blueteam.audit")
