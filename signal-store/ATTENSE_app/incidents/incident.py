from datetime import datetime 
from ATTENSE_app.events.event import Event 

class Incident:
    def __init__(self,incident_id: str, scenario_id: str):
        self.incident_id: str = incident_id
        self.scenario_id: str = scenario_id
        self.start_time: datetime | None = None 
        self.end_time: datetime | None = None
        self.detection_time: datetime | None = None
        self.containment_time: datetime | None = None
        self.status: str = "NOT_STARTED"
        self.events: list[Event] = []

    def apply_event(self, event: Event):#same input = same output "pure function"
        # Ignore events that belong to another incident
        if event.incident_id != self.incident_id:
            return
        self.events.append(event) #to add the events related to that incident   
        if event.event_type =="malicious_action_executed":
            if self.status=="NOT_STARTED" and self.start_time is None:
                self.start_time= event.timestamp
                self.status= "ACTIVE_UNDETECTED"
        if event.event_type =="alert_raised":
            # Detection anchor
            if self.detection_time is None:
                self.detection_time = event.timestamp
            # Phase-2 fallback:
            # If no attacker node exists, anchor start_time here.
            if self.start_time is None:
                self.start_time = event.timestamp
        if event.event_type =="incident_confirmed":
            if self.status=="ACTIVE_UNDETECTED" and self.detection_time is None:
                self.detection_time= event.timestamp
                self.status= "DETECTED"
        if event.event_type =="containment_succeeded":
            if self.status=="DETECTED" and self.containment_time is None:
                self.containment_time= event.timestamp
                self.status= "CONTAINED"
        if event.event_type =="incident_ended":
            if self.status != "NOT_STARTED" and self.end_time is None:
                self.end_time= event.timestamp
                self.status= "ENDED"

