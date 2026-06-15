from datetime import datetime 
from ATTENSE_app.events.event import Event 

class Incident:
    def __init__(self,incident_id: str, scenario_id: str):
        self.incident_id: str = incident_id
        self.scenario_id: str = scenario_id
        self.start_time: datetime | None = None 
        self.end_time: datetime | None = None
        self.detection_time: datetime | None = None
        self.investigation_time: datetime | None = None
        self.containment_start_time: datetime | None = None
        self.containment_time: datetime | None = None
        self.containment_failures: int = 0
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
            if self.start_time is None:
                self.start_time = event.timestamp
                
        if event.event_type == "alert_investigation_started":
            if self.investigation_time is None:
                self.investigation_time = event.timestamp
            if self.status in ["ACTIVE_UNDETECTED", "DETECTED", "NOT_STARTED"]:
                self.status = "INVESTIGATING"

        if event.event_type =="incident_confirmed":
            if self.status in ["ACTIVE_UNDETECTED", "NOT_STARTED", "INVESTIGATING"]:
                self.status= "DETECTED"
            if self.detection_time is None:
                self.detection_time= event.timestamp
                
        if event.event_type == "containment_initiated":
            if self.containment_start_time is None:
                self.containment_start_time = event.timestamp
            if self.status != "ENDED":
                self.status = "CONTAINING"
                
        if event.event_type == "containment_failed":
            self.containment_failures += 1
            if self.status != "ENDED":
                self.status = "CONTAINMENT_FAILED"

        if event.event_type =="containment_succeeded":
            if self.containment_time is None:
                self.containment_time= event.timestamp
            if self.status != "ENDED":
                self.status= "CONTAINED"
                
        if event.event_type == "alert_denied":
            if self.end_time is None:
                self.end_time = event.timestamp
            self.status = "FALSE_POSITIVE"

        if event.event_type =="incident_ended":
            if self.end_time is None:
                self.end_time= event.timestamp
            # If it's not already closed as a false positive, mark it ended
            if self.status != "FALSE_POSITIVE":
                self.status= "ENDED"

