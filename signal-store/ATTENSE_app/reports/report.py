from typing import Any

from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.matrics.metrics import TTC_calculation,TTD_calculation 
from ATTENSE_app.Outcomes.outcome import classify_outcome

def generate_report(incident: Incident) -> dict[str, Any]:
    ttd = TTD_calculation(incident)
    ttc = TTC_calculation(incident)
    outcome = classify_outcome(incident)

    return {
        "incident_id": incident.incident_id,
        "scenario_id": incident.scenario_id,
        "status": incident.status,

        "start_time": incident.start_time,
        "detection_time": incident.detection_time,
        "containment_time": incident.containment_time,
        "end_time": incident.end_time,

        "ttd": ttd,
        "ttc": ttc,

        "outcome": outcome,
    }
