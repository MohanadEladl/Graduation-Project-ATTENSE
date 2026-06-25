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
from typing import Optional

from fastapi import Header, HTTPException, status

from ..infrastructure.eventstore.event_emitter import EventEmitter
from ..infrastructure.thehive.hive_client import HiveClient
from ..infrastructure.sandbox.target_connector import TargetConnector
from ..infrastructure.sandbox.lab_evidence_connector import LabEvidenceConnector
from ..infrastructure.cortex.enrichment_service import EnrichmentService
from ..core.blueactions.attacker_log_attacher import AttackerLogAttacher
from ..config.settings import Settings


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


def get_lab_evidence_connector() -> LabEvidenceConnector:
    """Provide a read-only LabEvidenceConnector for attacker evidence."""
    settings = get_settings()
    return LabEvidenceConnector(base_url=settings.sandbox_url)


@lru_cache
def get_attacker_log_attacher() -> AttackerLogAttacher:
    """Provide the shared AttackerLogAttacher used by the Hive webhook.

    Cached so its in-memory "attach-once" guard survives across webhook calls,
    but built lazily on first use (not at import) so importing this module has
    no side effects / no eager Settings or network-client construction.
    """
    return AttackerLogAttacher(
        hive=get_hive_client(),
        lab_connector=get_lab_evidence_connector(),
    )


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


# ─────────────────────────────────────────────────────────────────────────────
# Authorization
# ─────────────────────────────────────────────────────────────────────────────

def require_room(
    x_room_id: Optional[str] = Header(default=None, alias="X-Room-Id"),
) -> str:
    """Authorize and scope every Blue Team action to a room (report Phase 5).

    The caller's room is taken from the `X-Room-Id` header (supplied by the
    control plane / gateway), NOT from the request body, so it cannot be
    forged to reach another room. A missing room is a 401. The data layer
    (EventEmitter) then enforces that the targeted incident belongs to this
    room, raising CrossRoomAccessError (→ 403) on a cross-room attempt.
    """
    if not x_room_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Room-Id header (room authorization required).",
        )
    return x_room_id
