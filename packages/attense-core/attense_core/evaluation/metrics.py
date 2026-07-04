from datetime import timedelta


from attense_core.models.incident import Incident

def TTD_calculation(incident: Incident) -> timedelta | None:
    if incident.start_time is None or incident.detection_time is None:
        return None
    return incident.detection_time - incident.start_time
    
def TTC_calculation(incident: Incident) -> timedelta | None:
    if incident.detection_time is None or incident.containment_time is None:
        return None
    return incident.containment_time - incident.detection_time
        