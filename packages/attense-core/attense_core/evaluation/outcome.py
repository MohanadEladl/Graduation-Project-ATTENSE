from attense_core.models.incident import Incident

def classify_outcome(incident: Incident) -> str:
  if is_false_positive(incident):
      return "FALSE_POSITIVE"

  match incident.status:
        case "ENDED":
            if incident.detection_time is None:
                return "FAILURE"
            if incident.containment_time is None:
                return "PARTIAL"
            return "SUCCESS"

        case _:
            return "INCOMPLETE"

def is_false_positive(incident: Incident) -> bool:
    events = incident.events
    #alerts occurred but no malicious action
    has_alert = any(
        event.event_type == "alert_raised"
        for event in events
    )

    return has_alert and incident.start_time is None
