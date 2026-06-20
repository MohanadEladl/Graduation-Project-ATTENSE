import json
import logging
import os
import threading
import time

import uvicorn

from ATTENSE_app.events.event import Event
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.reports.report import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("attense-controller")

DATA_PATH = os.getenv("ATTENSE_DATA_PATH", "/attense/data/mapped_events.jsonl")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))


class AttenseController:
    def __init__(self):
        self.incidents = {}
        self.last_pos = 0

    def process_event(self, event_data: dict):
        try:
            # Reconstruct the Event object from the JSON data
            # The Event constructor expects specific fields
            event = Event(
                event_id=event_data["event_id"],
                incident_id=event_data["incident_id"],
                scenario_id=event_data["scenario_id"],
                actor_id=event_data["actor_id"],
                target_id=event_data["target_id"],
                event_type=event_data["event_type"],
                actor_type=event_data["actor_type"],
                target_type=event_data["target_type"],
                timestamp=event_data["timestamp"],
                outcome=event_data.get("outcome"),
                metadata=event_data.get("metadata")
            )
            
            incident_id = event.incident_id
            if incident_id not in self.incidents:
                logger.info(f"New incident detected: {incident_id}")
                self.incidents[incident_id] = Incident(incident_id, event.scenario_id)
            
            incident = self.incidents[incident_id]
            incident.apply_event(event)
            
            # Generate a report after each event for real-time visibility
            report = generate_report(incident)
            logger.info(f"Updated report for {incident_id}: Outcome={report['outcome']}, Status={incident.status}")
            
        except Exception as e:
            logger.error(f"Failed to process event: {e}", exc_info=True)

    def run(self):
        logger.info(f"Starting Attense Controller, watching {DATA_PATH}")
        # Start Blue Team FastAPI app in background thread (served by this container)
        def _start_blueteam():
            try:
                # Import here to avoid import-time side effects when controller is used in tests
                from ATTENSE_app.blueteam.main import app as blueteam_app
                uvicorn.run(blueteam_app, host="0.0.0.0", port=8010, log_level="info")
            except Exception as e:
                logger.error(f"Failed to start Blue Team app: {e}", exc_info=True)

        t = threading.Thread(target=_start_blueteam, daemon=True)
        t.start()
        
        while True:
            if not os.path.exists(DATA_PATH):
                time.sleep(POLL_INTERVAL)
                continue
            
            try:
                with open(DATA_PATH, "r") as f:
                    f.seek(self.last_pos)
                    for line in f:
                        if not line.strip():
                            continue
                        event_data = json.loads(line)
                        self.process_event(event_data)
                    self.last_pos = f.tell()
            except Exception as e:
                logger.error(f"Error reading data file: {e}")
            
            time.sleep(POLL_INTERVAL)
