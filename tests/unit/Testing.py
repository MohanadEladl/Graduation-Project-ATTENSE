"""
Testing script for ATTENSE_app

Legacy/superseded (see tests/README.md "Note on the legacy Testing.py"):
predates the alert_raised start-time fallback, so test_false_positive_case
fails against current code. Kept for historical reference, not run by CI.
"""
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PKG_ROOT = os.path.join(_REPO_ROOT, "apps", "control-api")
_CORE_ROOT = os.path.join(_REPO_ROOT, "packages", "attense-core")
for _p in (_PKG_ROOT, _CORE_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from datetime import datetime, timedelta
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.events.event import Event
from ATTENSE_app.reports.report import generate_report
#test outcomes with metrix 
def test_success_case():
    print("Running Success Case...")
    incident = Incident("INC-1", "SCN-1")

    base_time = datetime(2026, 1, 1, 10, 0, 0)

    events = [
        Event(event_id="E1", incident_id="INC-1", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="malicious_action_executed", actor_type="red_team", target_type="service", timestamp=base_time),
        Event(event_id="E2", incident_id="INC-1", scenario_id="SCN-1", actor_id="actor-2", target_id="target-2", event_type="incident_confirmed", actor_type="blue_team", target_type="alert", timestamp=base_time + timedelta(minutes=4)),
        Event(event_id="E3", incident_id="INC-1", scenario_id="SCN-1", actor_id="actor-2", target_id="target-3", event_type="containment_succeeded", actor_type="blue_team", target_type="host", timestamp=base_time + timedelta(minutes=9)),
        Event(event_id="E4", incident_id="INC-1", scenario_id="SCN-1", actor_id="actor-3", target_id="target-4", event_type="incident_ended", actor_type="system", target_type="service", timestamp=base_time + timedelta(minutes=12)),
    ]

    for e in events:
        incident.apply_event(e)

    report = generate_report(incident)
    print("Actual outcome:", report["outcome"])

    assert report["outcome"] == "SUCCESS", f"Expected SUCCESS, got {report['outcome']}"
    assert report["ttd"] == timedelta(minutes=4)
    assert report["ttc"] == timedelta(minutes=5)
    print("Test Success Case Passed\n")

def test_partial_case():
    print("Running Partial Case...")
    incident = Incident("INC-2", "SCN-1")
    base_time = datetime(2026, 1, 1, 11, 0, 0)

    events = [
        Event(event_id="E1", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="malicious_action_executed", actor_type="red_team", target_type="service", timestamp=base_time + timedelta(minutes=2)),
        Event(event_id="E2", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-2", target_id="target-2", event_type="incident_confirmed", actor_type="blue_team", target_type="alert", timestamp=base_time + timedelta(minutes=4)),
        Event(event_id="E3", incident_id="INC-2", scenario_id="SCN-1", actor_id="actor-3", target_id="target-4", event_type="incident_ended", actor_type="system", target_type="service", timestamp=base_time + timedelta(minutes=10)),
    ]

    for e in events:
        incident.apply_event(e)

    report = generate_report(incident)
    print("Actual outcome:", report["outcome"])

    assert report["outcome"] == "PARTIAL", f"Expected PARTIAL, got {report['outcome']}"
    assert report["ttd"] == timedelta(minutes=2), f"Expected 2m TTD, got {report['ttd']}"
    assert report["ttc"] is None
    print("Test Partial Case Passed\n")

def test_failure_case():
    print("Running Failure Case...")
    incident = Incident("INC-3", "SCN-1")
    base_time = datetime(2026, 1, 1, 12, 0, 0)

    events = [
        Event(event_id="E1", incident_id="INC-3", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="malicious_action_executed", actor_type="red_team", target_type="service", timestamp=base_time),
        Event(event_id="E2", incident_id="INC-3", scenario_id="SCN-1", actor_id="actor-3", target_id="target-4", event_type="incident_ended", actor_type="system", target_type="service", timestamp=base_time + timedelta(minutes=10)),
    ]

    for e in events:
        incident.apply_event(e)

    report = generate_report(incident)
    print("Actual outcome:", report["outcome"])

    assert report["outcome"] == "FAILURE", f"Expected FAILURE, got {report['outcome']}"
    assert report["ttd"] is None
    assert report["ttc"] is None
    print("Test Failure Case Passed\n")

def test_false_positive_case():
    print("Running False Positive Case...")
    incident = Incident("INC-4", "SCN-1")
    base_time = datetime(2026, 1, 1, 13, 0, 0)

    events = [
        Event(event_id="E1", incident_id="INC-4", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="alert_raised", actor_type="blue_team", target_type="alert", timestamp=base_time),
    ]

    for e in events:
        incident.apply_event(e)

    report = generate_report(incident)
    print("Actual outcome:", report["outcome"])

    assert report["outcome"] == "FALSE_POSITIVE", f"Expected FALSE_POSITIVE, got {report['outcome']}"
    assert report["ttd"] is None
    assert report["ttc"] is None
    print("Test False Positive Case Passed\n")

def test_incomplete_case():
    print("Running Incomplete Case...")
    incident = Incident("INC-5", "SCN-1")
    base_time = datetime(2026, 1, 1, 14, 0, 0)

    events = [
        Event(event_id="E1", incident_id="INC-5", scenario_id="SCN-1", actor_id="actor-1", target_id="target-1", event_type="malicious_action_executed", actor_type="red_team", target_type="service", timestamp=base_time),
    ]

    for e in events:
        incident.apply_event(e)

    report = generate_report(incident)
    print("Actual outcome:", report["outcome"])

    assert report["outcome"] == "INCOMPLETE", f"Expected INCOMPLETE, got {report['outcome']}"
    assert report["ttd"] is None
    assert report["ttc"] is None
    print("Test Incomplete Case Passed\n")

if __name__ == "__main__":
    test_success_case()
    test_partial_case()
    test_failure_case()
    test_false_positive_case()
    test_incomplete_case()
