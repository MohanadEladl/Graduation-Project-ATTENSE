
from datetime import datetime, timedelta

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report


def run_simulator():#report

    incident = Incident(
        incident_id="INC-001",
        scenario_id="SCN-BRUTE-FORCE"
    )

    base_time = datetime.now()


    events = [
        Event(event_id="E1", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="malicious_action_executed", actor_type="red_team", target_type="service", timestamp=base_time + timedelta(minutes=2)),
        Event(event_id="E2", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-2", target_id="target-2", event_type="incident_confirmed", actor_type="blue_team", target_type="alert", timestamp=base_time + timedelta(minutes=4)),
        Event(event_id="E3", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-3", target_id="target-4", event_type="incident_ended", actor_type="system", target_type="service", timestamp=base_time + timedelta(minutes=10)),
    ]

    for event in events:
        incident.apply_event(event)

    report = generate_report(incident)

    print("\n=== Incident Simulation Report ===")
    for key, value in report.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    run_simulator()
