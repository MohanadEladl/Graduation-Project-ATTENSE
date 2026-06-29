"""Durable, idempotent JSON-backed event repository (Phase 3).

Events and incidents are treated as logs, so the durable record is an
append-only JSONL file (`events.jsonl`) -- one `StandardEvent` per line, in
insertion order -- which is the most log-like, inspectable form and consistent
with the existing `mapped_events.jsonl`. The incident projection is a derived
snapshot kept in `incidents.json`; it is always rebuildable from the event log,
so a crash between the event append and the projection write self-heals on the
next load (`rebuild_projection`).

This keeps the storage-agnostic `EventRepository` / `IncidentProjection`
interface: a real database (SQLite/Postgres) can replace this backend at the end
without touching the contract, the controller wiring, or these tests.

What it provides over the old raw JSONL bus:
  - idempotency: a replayed event (same `event_id`) is ignored, fixing the
    Phase 1 double-counting gap;
  - one ordered timeline per incident;
  - the event + projection updated together, projection rebuildable from the log;
  - durable appends (flush + fsync) that survive restarts.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from attense_core.models.standard_event import StandardEvent
from attense_core.repositories.incidents import IncidentProjection

logger = logging.getLogger("attense-persistence")

EVENTS_FILENAME = "events.jsonl"
INCIDENTS_FILENAME = "incidents.json"


class EventRepository:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.events_path = os.path.join(base_dir, EVENTS_FILENAME)
        self.incidents_path = os.path.join(base_dir, INCIDENTS_FILENAME)
        self._events_by_incident: Dict[str, List[StandardEvent]] = defaultdict(list)
        self._seen_ids: set[str] = set()
        self._projections: Dict[str, dict] = {}
        self._load()

    # ── Write ────────────────────────────────────────────────────────────────
    def append(self, event: StandardEvent) -> bool:
        """Append one event durably and refresh its incident projection.

        Returns True if stored, False if it was a duplicate (same event_id) and
        therefore ignored.
        """
        if event.event_id in self._seen_ids:
            return False

        self._append_event_line(event)
        self._seen_ids.add(event.event_id)

        events = self._events_by_incident[event.incident_id]
        events.append(event)
        events.sort(key=lambda e: e.occurred_at)  # stable: ties keep insertion order

        projection = IncidentProjection.from_events(
            event.incident_id, event.scenario_id, events
        )
        self._projections[event.incident_id] = self._projection_record(projection)
        self._write_incidents()

        if projection.anomalies:
            logger.warning(
                "Incident %s has %d out-of-order event(s): %s",
                event.incident_id,
                len(projection.anomalies),
                projection.anomalies,
            )
        return True

    # ── Read ─────────────────────────────────────────────────────────────────
    def get_events(self, incident_id: str) -> List[StandardEvent]:
        """All events for an incident, ordered by occurred_at then insertion."""
        return list(self._events_by_incident.get(incident_id, []))

    def get_projection(self, incident_id: str) -> Optional[IncidentProjection]:
        """The stored incident projection, or None if the incident is unknown."""
        record = self._projections.get(incident_id)
        return IncidentProjection.from_dict(record) if record is not None else None

    def rebuild_projection(self, incident_id: str) -> Optional[IncidentProjection]:
        """Recompute the projection from the durable events (restart recovery)."""
        events = self._events_by_incident.get(incident_id)
        if not events:
            return None
        projection = IncidentProjection.from_events(
            incident_id, events[0].scenario_id, events
        )
        self._projections[incident_id] = self._projection_record(projection)
        self._write_incidents()
        return projection

    def all_incident_ids(self) -> List[str]:
        return sorted(self._projections.keys())

    # ── Persistence helpers ──────────────────────────────────────────────────
    def _load(self) -> None:
        """Rebuild in-memory state from the durable files on startup."""
        if os.path.exists(self.events_path):
            with open(self.events_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    event = StandardEvent.model_validate(json.loads(line))
                    if event.event_id in self._seen_ids:
                        continue  # defensive de-dup if the log ever has a repeat
                    self._seen_ids.add(event.event_id)
                    self._events_by_incident[event.incident_id].append(event)
            for events in self._events_by_incident.values():
                events.sort(key=lambda e: e.occurred_at)

        if os.path.exists(self.incidents_path):
            with open(self.incidents_path, encoding="utf-8") as fh:
                self._projections = json.load(fh)

    def _append_event_line(self, event: StandardEvent) -> None:
        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
        with open(self.events_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _write_incidents(self) -> None:
        """Atomically rewrite the projection snapshot (temp file + replace)."""
        tmp = self.incidents_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._projections, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        self._replace_file(tmp, self.incidents_path)

    @staticmethod
    def _replace_file(src: str, dst: str) -> None:
        """Replace a file, retrying transient Windows file-lock failures."""
        last_error: OSError | None = None
        for _ in range(5):
            try:
                os.replace(src, dst)
                return
            except PermissionError as exc:
                last_error = exc
                time.sleep(0.05)
        try:
            if os.path.exists(dst):
                os.remove(dst)
            os.replace(src, dst)
            return
        except OSError as exc:
            last_error = exc
        try:
            shutil.copyfile(src, dst)
            try:
                os.remove(src)
            except OSError:
                pass
            return
        except OSError as exc:
            last_error = exc
        if last_error is not None:
            raise last_error

    @staticmethod
    def _projection_record(projection: IncidentProjection) -> dict:
        record = projection.to_dict()
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        return record
