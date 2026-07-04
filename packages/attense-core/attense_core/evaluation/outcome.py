from attense_core.models.incident import Incident

def classify_outcome(incident: Incident) -> str:
    if is_false_positive(incident):
        return "FALSE_POSITIVE"

    # CONTAINED is the highest status in a normal exercise run.
    # ENDED requires an explicit incident_ended event which the room
    # close flow does not fire, so treat both as fully resolved.
    if incident.status in {"ENDED", "CONTAINED"}:
        if incident.detection_time is None:
            return "FAILURE"
        if incident.containment_time is None:
            return "PARTIAL"
        return "SUCCESS"

    if incident.status == "CONTAINMENT_FAILED":
        return "FAILURE" if incident.detection_time is None else "PARTIAL"

    return "INCOMPLETE"

def is_false_positive(incident: Incident) -> bool:
    events = incident.events
    #alerts occurred but no malicious action
    has_alert = any(
        event.event_type == "alert_raised"
        for event in events
    )

    return has_alert and incident.start_time is None
