from collections import defaultdict
from typing import List
from ATTENSE_app.events.event import Event

class EventStore:
    def __init__(self):
        self._events = defaultdict(list)

    def add_event(self, event: Event):
        self._events[event.incident_id].append(event)

    def get_events(self, incident_id: str) -> List[Event]:
        return self._events.get(incident_id, [])

    def has_event(self, incident_id: str, event_type: str) -> bool:
        return any(
            e.event_type == event_type
            for e in self._events.get(incident_id, [])
        )
