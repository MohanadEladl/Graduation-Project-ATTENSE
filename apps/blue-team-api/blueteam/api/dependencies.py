"""
dependencies.py - Dependency Injection for Blue Team API
=========================================================
Provides shared dependencies that are injected into route handlers
via FastAPI's Depends() mechanism.

Instead of creating services inside every route, components are
supplied from outside (the military supplies the rifle, not the soldier).

Injected dependencies:
    - EventStore : in-memory event log (swap for DB/Kafka in production)
    - HiveClient : TheHive integration (stubbed until Hive is live)
    - SandboxConnector : controls the target sandbox environment
    - Logger : audit-trail logger
    - Settings : runtime config
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from attense_core.security.session_auth import get_session

from ..infrastructure.eventstore.event_emitter import EventEmitter
from ..infrastructure.thehive.hive_client import HiveClient
from ..infrastructure.thehive.room_hive_registry import resolve_room_hive_api_key, resolve_room_owner, room_hive_org_pending
from ..infrastructure.sandbox.target_connector import TargetConnector
from ..infrastructure.sandbox.lab_evidence_connector import LabEvidenceConnector
from ..infrastructure.cortex.enrichment_service import EnrichmentService
from ..core.blueactions.attacker_log_attacher import AttackerLogAttacher
from ..config.settings import Settings
from ..utils.permissions import require_permission as _require_permission

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Settings singleton
# -----------------------------------------------------------------------------

@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (reads env vars once)."""
    return Settings()


# -----------------------------------------------------------------------------
# Infrastructure singletons
# -----------------------------------------------------------------------------

# Single shared EventEmitter - all routes publish through the same store.
_event_emitter = EventEmitter()


def get_event_emitter() -> EventEmitter:
    """Provide the shared EventEmitter (event store wrapper)."""
    return _event_emitter


def get_hive_client() -> HiveClient:
    """Provide a HiveClient using the global HIVE_API_KEY (shared org).

    Room-scoped callers should use `get_room_scoped_hive_client` /
    `build_hive_client_for_room` instead so alerts/cases land in that room's
    own TheHive organisation rather than this shared fallback.
    """
    settings = get_settings()
    return HiveClient(base_url=settings.hive_url, api_key=settings.hive_api_key)


def build_hive_client_for_room(room_id: Optional[str]) -> HiveClient:
    """Provide a HiveClient scoped to *room_id*'s own TheHive org, when known.

    A *known* room with no dedicated key yet (e.g. a deferred exercise whose
    alerts fire before any Blue Team member has entered the room and
    triggered provisioning - see `core.room_manager._ensure_room_hive`) gets
    a disabled client instead of the global shared org: writing this room's
    alert into some OTHER room's org was the exact cross-room leak reported
    against the old shared "blue-team" org. The room's own /replay-alerts
    call delivers this correctly once its dedicated org exists.

    Falls back to the global HIVE_API_KEY only when there's genuinely no room
    context to isolate (room_id is None/"system") or when running the
    standalone per-room container where `core` isn't importable at all (no
    room registry to consult either way).
    """
    settings = get_settings()
    if room_hive_org_pending(room_id):
        logger.info(
            "[dependencies] Room %s has no dedicated Hive org yet - using a "
            "disabled Hive client instead of the shared fallback org.",
            room_id,
        )
        return HiveClient(base_url=settings.hive_url, api_key="")
    api_key = resolve_room_hive_api_key(room_id) or settings.hive_api_key
    return HiveClient(base_url=settings.hive_url, api_key=api_key)


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
        hive_resolver=build_hive_client_for_room,
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


# -----------------------------------------------------------------------------
# Authorization
# -----------------------------------------------------------------------------

def require_room(
    x_room_id: Optional[str] = Header(default=None, alias="X-Room-Id"),
) -> str:
    """Authorize and scope every Blue Team action to a room (report Phase 5).

    The caller's room is taken from the `X-Room-Id` header (supplied by the
    control plane / gateway), NOT from the request body, so it cannot be
    forged to reach another room. A missing room is a 401. The data layer
    (EventEmitter) then enforces that the targeted incident belongs to this
    room, raising CrossRoomAccessError (-> 403) on a cross-room attempt.
    """
    if not x_room_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Room-Id header (room authorization required).",
        )
    return x_room_id


def get_room_scoped_hive_client(room_id: str = Depends(require_room)) -> HiveClient:
    """FastAPI dependency: a HiveClient scoped to the caller's X-Room-Id.

    Use this (not `get_hive_client`) in any route that raises alerts or
    creates/updates cases, so the write lands in that room's own TheHive
    organisation instead of the shared fallback org.
    """
    return build_hive_client_for_room(room_id)


def get_current_session(
    x_session_token: Optional[str] = Header(default=None),
) -> dict:
    """Resolve the calling analyst's session (username/role) from their login
    token - the same X-Session-Token control-api's require_session checks,
    read here via the shared attense_core reader since this service doesn't
    own session lifecycle (see attense_core.security.session_auth).
    """
    if not x_session_token:
        raise HTTPException(status_code=401, detail="Missing X-Session-Token (login required).")
    session = get_session(x_session_token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return session


# Actions a room's owner (its soc_manager_username - whoever started/entered
# it, including a solo soc_l1 player) may perform in THAT room even when
# their base account role wouldn't otherwise allow it. Scoped narrowly to
# complete_containment: a solo soc_l1 can initiate containment (their base
# role already allows start_containment) but, without this, could never
# finish their own exercise, since complete_containment is normally an
# soc_l2+ escalation step.
ROOM_OWNER_ESCALATABLE_ACTIONS = {"complete_containment"}


def require_permission(action: str):
    """FastAPI dependency factory: 403s unless the caller's role may perform
    *action*, per blueteam.utils.permissions.ROLE_PERMISSIONS - or the caller
    owns this specific room and *action* is room-owner-escalatable (see
    ROOM_OWNER_ESCALATABLE_ACTIONS above).
    """
    def _check(
        session: dict = Depends(get_current_session),
        room_id: str = Depends(require_room),
    ) -> dict:
        try:
            _require_permission(session.get("role", ""), action)
        except PermissionError as exc:
            if action in ROOM_OWNER_ESCALATABLE_ACTIONS and (
                session.get("username") and session["username"] == resolve_room_owner(room_id)
            ):
                return session
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return session
    return _check
