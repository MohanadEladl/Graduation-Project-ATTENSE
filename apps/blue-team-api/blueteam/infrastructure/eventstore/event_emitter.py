"""
event_emitter.py — Event Store Wrapper (Infrastructure Layer)
==============================================================
Wraps the ATTENSE_app EventStore and Incident registry.

Provides a single interface to:
    - get_or_create()  : fetch or create incident + store pair (room-scoped)
    - emit()           : persist event and apply it to incident state

Tenant isolation (report Phase 5): every incident is owned by the room that
first created it. A call from a different room raises CrossRoomAccessError, so
two rooms sharing one Blue Team instance can never read or modify each other's
incidents. The room boundary is enforced here, in the data layer, not only at
the API edge.

In production the in-memory registry would be swapped for a Kafka/PostgreSQL
backed store (with room_id as a tenant key) without touching any service or
router code (that is the point of DI).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, Optional, Tuple

from ATTENSE_app.events.event import Event
from ATTENSE_app.events.event_store import EventStore
from ATTENSE_app.incidents.incident import Incident

logger = logging.getLogger(__name__)


class CrossRoomAccessError(PermissionError):
    """Raised when a caller tries to read/modify an incident owned by a
    different room. Enforces tenant isolation in the data layer."""


class EventEmitter:
    """
    Manages the in-memory incident registry and event store.

    Attributes
    ----------
    _incidents : dict[str, Incident]
        Map of incident_id → Incident object.
    _stores    : dict[str, EventStore]
        Map of incident_id → EventStore (event log).
    _incident_rooms : dict[str, str]
        Map of incident_id → owning room_id (tenant key).
    """

    def __init__(self) -> None:
        self._incidents: Dict[str, Incident] = {}
        self._stores: Dict[str, EventStore] = defaultdict(EventStore)
        self._incident_rooms: Dict[str, str] = {}

    def _check_room(self, room_id: str, incident_id: str) -> None:
        """Raise if `incident_id` exists and is owned by a different room."""
        owner = self._incident_rooms.get(incident_id)
        if owner is not None and owner != room_id:
            raise CrossRoomAccessError(
                f"Incident '{incident_id}' belongs to room '{owner}', "
                f"not '{room_id}'."
            )

    def room_of(self, incident_id: str) -> Optional[str]:
        """Return the room that owns an incident, or None if unknown."""
        return self._incident_rooms.get(incident_id)

    def get_or_create(
        self, room_id: str, incident_id: str, scenario_id: str
    ) -> Tuple[Incident, EventStore]:
        """
        Return the (Incident, EventStore) pair for this incident_id within the
        caller's room, creating them on first use.

        The incident is tagged with the room that first created it. A later call
        from a *different* room raises CrossRoomAccessError.

        Parameters
        ----------
        room_id     : Authorized room the caller is acting within.
        incident_id : Unique identifier for the incident.
        scenario_id : Scenario context for the incident.
        """
        self._check_room(room_id, incident_id)
        if incident_id not in self._incidents:
            self._incidents[incident_id] = Incident(incident_id, scenario_id)
            self._incident_rooms[incident_id] = room_id
            logger.info(
                "[EventEmitter] New incident created: %s (room=%s)",
                incident_id, room_id,
            )
        return self._incidents[incident_id], self._stores[incident_id]

    def emit(self, incident: Incident, store: EventStore, event: Event) -> None:
        """
        Persist an event and advance incident state atomically.

        Steps:
            1. Validate that event belongs to the given incident.
            2. Add event to the EventStore (durable record).
            3. Call incident.apply_event() to update timestamps/status.

        Raises
        ------
        ValueError : If event.incident_id does not match incident.incident_id.
        """
        if event.incident_id != incident.incident_id:
            raise ValueError(
                f"Event incident_id '{event.incident_id}' does not match "
                f"incident '{incident.incident_id}'."
            )
        try:
            store.add_event(event)
            incident.apply_event(event)
        except Exception as e:
            # Architectural Issue: If apply_event fails, we lose consistency between
            # the store and the incident state.
            # Later in production, you'd use:
            # - Transactions
            # - Rollback
            # - Message queues
            logger.error("Failed to apply event. Architectural atomicity issue: %s", e)
            raise

        logger.debug(
            "[EventEmitter] Event stored: type=%s id=%s → incident=%s status=%s",
            event.event_type, event.event_id,
            incident.incident_id, incident.status,
        )

    def get_incident(self, room_id: str, incident_id: str) -> Optional[Incident]:
        """Return an existing Incident by ID within the caller's room, or None
        if not found. Raises CrossRoomAccessError if it belongs to another room."""
        self._check_room(room_id, incident_id)
        return self._incidents.get(incident_id)

    def get_store(self, incident_id: str) -> EventStore:
        """Return the EventStore for a given incident_id."""
        return self._stores[incident_id]

    def all_incidents(self, room_id: Optional[str] = None) -> Dict[str, Incident]:
        """Return tracked incidents. If room_id is given, only that room's
        incidents (room-scoped query); otherwise all (admin/inspection)."""
        if room_id is None:
            return dict(self._incidents)
        return {
            iid: inc
            for iid, inc in self._incidents.items()
            if self._incident_rooms.get(iid) == room_id
        }
