from __future__ import annotations
from datetime import datetime
from attense_core.models.allowed_events import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_ACTOR_TYPES,
    ALLOWED_TARGET_TYPES,
    ALLOWED_OUTCOMES,
)

class Event:
    def __init__(self, event_id: str, incident_id: str, scenario_id: str, actor_id: str, target_id: str, event_type: str, actor_type: str, target_type: str, timestamp=None, outcome=None, metadata=None):
        self.event_id = event_id
        self.incident_id = incident_id
        self.scenario_id = scenario_id
        self.actor_id = actor_id
        self.target_id = target_id
        
        # Validate and set types (using internal methods to validate and return value)
        self.event_type = self._validate_event_type(event_type)
        self.actor_type = self._validate_actor_type(actor_type)
        self.target_type = self._validate_target_type(target_type)
        
        # Handle timestamp (default to now if None)
        if timestamp is None:
            timestamp = datetime.now()
        self.timestamp = self._parse_timestamp(timestamp)
        
        self.outcome = self._validate_outcome(outcome)
        self.metadata = metadata

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "incident_id": self.incident_id,
            "scenario_id": self.scenario_id,
            "actor_id": self.actor_id,
            "target_id": self.target_id,
            "event_type": self.event_type,
            "actor_type": self.actor_type,
            "target_type": self.target_type,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "outcome": self.outcome,
            "metadata": self.metadata
        }

    def __str__(self):
        return f"Event ID: {self.event_id}, Incident ID: {self.incident_id}, Scenario ID: {self.scenario_id}, Event Type: {self.event_type}, Actor Type: {self.actor_type}, Target Type: {self.target_type}, Timestamp: {self.timestamp}, Outcome: {self.outcome}, Metadata: {self.metadata}"

    def _parse_timestamp(self, timestamp) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp)
            except ValueError:
                raise ValueError("timestamp must be in ISO 8601 format")
        raise TypeError("timestamp must be a datetime object or ISO 8601 string")

    def _validate_event_type(self, event_type: str) -> str:
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"event_type '{event_type}' is not valid. Must be one of: {', '.join(sorted(ALLOWED_EVENT_TYPES))}")
        return event_type

    def _validate_actor_type(self, actor_type: str) -> str:
        if actor_type not in ALLOWED_ACTOR_TYPES:
            raise ValueError(f"actor_type '{actor_type}' is not valid. Must be one of: {', '.join(sorted(ALLOWED_ACTOR_TYPES))}")
        return actor_type

    def _validate_target_type(self, target_type: str) -> str:
        if target_type not in ALLOWED_TARGET_TYPES:
            raise ValueError(f"target_type '{target_type}' is not valid. Must be one of: {', '.join(sorted(ALLOWED_TARGET_TYPES))}")
        return target_type

    def _validate_outcome(self, outcome: str | None) -> str | None:
        if outcome is None:
            return None
        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError(f"outcome '{outcome}' is not valid. Must be one of: {', '.join(sorted(ALLOWED_OUTCOMES))}")
        return outcome
