"""
event_emitter.py — Event Store Wrapper (Infrastructure Layer)
==============================================================
Wraps the ATTENSE_app EventStore and Incident registry.

Provides a single interface to:
    - get_or_create()  : fetch or create incident + store pair
    - emit()           : persist event and apply it to incident state

In production this would be swapped for a Kafka/PostgreSQL backed store
without touching any service or router code (that is the point of DI).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, Tuple

from ATTENSE_app.events.event import Event
from ATTENSE_app.events.event_store import EventStore
from ATTENSE_app.incidents.incident import Incident

logger = logging.getLogger(__name__)


class EventEmitter:
    """
    Manages the in-memory incident registry and event store.

    Attributes
    ----------
    _incidents : dict[str, Incident]
        Map of incident_id → Incident object.
    _stores    : dict[str, EventStore]
        Map of incident_id → EventStore (event log).
    """

    def __init__(self) -> None:
        self._incidents: Dict[str, Incident] = {}
        self._stores: Dict[str, EventStore] = defaultdict(EventStore)

    def get_or_create(
        self, incident_id: str, scenario_id: str
    ) -> Tuple[Incident, EventStore]:
        """
        Return the existing (Incident, EventStore) pair for this incident_id,
        or create new ones if this is the first call for this id.

        Parameters
        ----------
        incident_id : Unique identifier for the incident.
        scenario_id : Scenario context for the incident.

        Returns
        -------
        (Incident, EventStore) tuple ready for use.
        """
        if incident_id not in self._incidents:
            self._incidents[incident_id] = Incident(incident_id, scenario_id)
            logger.info("[EventEmitter] New incident created: %s", incident_id)
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

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an existing Incident by ID, or None if not found."""
        return self._incidents.get(incident_id)

    def get_store(self, incident_id: str) -> EventStore:
        """Return the EventStore for a given incident_id."""
        return self._stores[incident_id]
    def all_incidents(self) -> Dict[str, Incident]:
        """Return all tracked incidents (for inspection endpoints)."""
        return dict(self._incidents)
