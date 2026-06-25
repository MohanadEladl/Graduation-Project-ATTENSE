import json
import logging
import os
import threading
import time

import uvicorn

from ATTENSE_app.events.event import Event
from ATTENSE_app.events.standard_event import StandardEvent
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
        self._blueteam_ready = threading.Event()
        self._blueteam_error = None
        self._blueteam_thread = None
        # Durable JSON event store (Phase 3). Disabled unless
        # ATTENSE_EVENT_STORE_DIR is set, so existing deployments are
        # byte-for-byte unchanged until they opt in.
        self.event_repository = None
        self._init_durable_store()

    def _init_durable_store(self):
        """Open the durable JSON event store if ATTENSE_EVENT_STORE_DIR is set.

        Dual-write target alongside the in-memory registry (report Phase 3,
        step 4). Any failure here leaves the controller running on the legacy
        in-memory path -- the durable store is additive, never a hard dependency.
        """
        store_dir = os.getenv("ATTENSE_EVENT_STORE_DIR")
        if not store_dir:
            return
        try:
            from ATTENSE_app.persistence.event_repository import EventRepository

            self.event_repository = EventRepository(store_dir)
            logger.info(f"Durable event store enabled at {store_dir}")
        except Exception as e:
            logger.error(
                f"Failed to initialize durable event store at {store_dir}: {e}",
                exc_info=True,
            )
            self.event_repository = None

    def blueteam_status(self) -> dict:
        """Return the observed state of the embedded Blue Team API."""
        thread_alive = self._blueteam_thread is not None and self._blueteam_thread.is_alive()
        return {
            "healthy": self._blueteam_ready.is_set() and thread_alive,
            "thread_alive": thread_alive,
            "error": self._blueteam_error,
        }

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
                # Link the incident back to its room, if one matches.
                try:
                    from core import room_manager
                    room_id = room_manager.find_room_id_for_incident(incident_id)
                    if room_id:
                        room_manager.add_incident(room_id, incident_id)
                except Exception as e:
                    logger.warning(f"Could not associate incident {incident_id} with a room: {e}")

            incident = self.incidents[incident_id]
            incident.apply_event(event)

            # Generate a report after each event for real-time visibility
            report = generate_report(incident)
            logger.info(f"Updated report for {incident_id}: Outcome={report['outcome']}, Status={incident.status}")

            # Dual-write to the durable store (Phase 3). Additive: its own
            # failures are logged, never propagated, so the in-memory path above
            # is the source of truth until reads are switched over (steps 6-7).
            self._durable_write(event_data)

        except Exception as e:
            logger.error(f"Failed to process event: {e}", exc_info=True)

    def _durable_write(self, event_data: dict):
        """Append the event to the durable repository if one is configured."""
        if self.event_repository is None:
            return
        try:
            std = self._standard_event_from_legacy(event_data)
            inserted = self.event_repository.append(std)
            if not inserted:
                logger.info(
                    f"Durable store ignored duplicate event_id={std.event_id}"
                )
        except Exception as e:
            logger.error(
                f"Durable write failed for event {event_data.get('event_id')}: {e}",
                exc_info=True,
            )

    @staticmethod
    def _standard_event_from_legacy(event_data: dict) -> StandardEvent:
        """Adapt a legacy event dict (the controller's wire/file format) into a
        StandardEvent. Correlation/contract fields the legacy bridge folds into
        metadata (source/room_id/run_id/source_event_id/schema_version) are
        promoted back to top level by StandardEvent itself, so file-tail (Wazuh)
        events that carry e.g. source_event_id in metadata keep full fidelity."""
        return StandardEvent.from_ingest_payload(event_data)

    def run(self):
        logger.info(f"Starting Attense Controller, watching {DATA_PATH}")
        # Start Blue Team FastAPI app in background thread (served by this container)
        def _start_blueteam():
            try:
                # Import here to avoid import-time side effects when controller is used in tests
                from blueteam.main import app as blueteam_app

                self._blueteam_error = None
                self._blueteam_ready.set()
                uvicorn.run(blueteam_app, host="0.0.0.0", port=8010, log_level="info")
                self._blueteam_error = "Blue Team API server stopped unexpectedly"
            except Exception as e:
                self._blueteam_error = f"{type(e).__name__}: {e}"
                logger.error(f"Failed to start Blue Team app: {e}", exc_info=True)
            finally:
                self._blueteam_ready.clear()

        self._blueteam_thread = threading.Thread(
            target=_start_blueteam,
            name="blueteam-api",
            daemon=True,
        )
        self._blueteam_thread.start()
        
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
