"""Incident projection derived from the durable event timeline (Phase 3).

`IncidentProjection.from_events` folds an ordered list of `StandardEvent`s into
the current incident state + metrics. It deliberately *reuses* the legacy
`Incident.apply_event` and the existing TTD/TTC and outcome functions, so the
projection's computed state is identical to today's behaviour (pinned by the
Phase 1 characterization tests) — the durability and idempotency come from the
repository/storage layer, not from changing the evaluation semantics.

Because the projection is rebuilt from the durable log, it survives restarts:
drop the process, reopen the DB, replay `from_events`, and you get the same
state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from attense_core.models.standard_event import StandardEvent
from attense_core.models.incident import Incident
from attense_core.evaluation.metrics import TTC_calculation, TTD_calculation
from attense_core.evaluation.outcome import classify_outcome
from attense_core.evaluation.state_machine import is_expected


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else value


@dataclass
class IncidentProjection:
    incident_id: str
    scenario_id: Optional[str]
    status: str
    start_time: Optional[datetime] = None
    detection_time: Optional[datetime] = None
    investigation_time: Optional[datetime] = None
    containment_start_time: Optional[datetime] = None
    containment_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    containment_failures: int = 0
    ttd_seconds: Optional[float] = None
    ttc_seconds: Optional[float] = None
    outcome: str = "INCOMPLETE"
    # Events that arrived out of the expected order (advisory; see transitions.py)
    anomalies: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_events(
        cls,
        incident_id: str,
        scenario_id: Optional[str],
        events: list[StandardEvent],
    ) -> "IncidentProjection":
        """Replay events (assumed ordered, deduplicated) into a projection."""
        inc = Incident(incident_id, scenario_id or "")
        anomalies: list[dict[str, str]] = []

        for ev in events:
            status_before = inc.status
            event_type = ev.event_type.value
            if not is_expected(status_before, event_type):
                anomalies.append(
                    {
                        "event_id": ev.event_id,
                        "event_type": event_type,
                        "status_before": status_before,
                        "reason": "unexpected transition for current status",
                    }
                )
            inc.apply_event(ev.to_legacy_event())

        ttd = TTD_calculation(inc)
        ttc = TTC_calculation(inc)
        return cls(
            incident_id=incident_id,
            scenario_id=scenario_id,
            status=inc.status,
            start_time=inc.start_time,
            detection_time=inc.detection_time,
            investigation_time=inc.investigation_time,
            containment_start_time=inc.containment_start_time,
            containment_time=inc.containment_time,
            end_time=inc.end_time,
            containment_failures=inc.containment_failures,
            ttd_seconds=ttd.total_seconds() if ttd is not None else None,
            ttc_seconds=ttc.total_seconds() if ttc is not None else None,
            outcome=classify_outcome(inc),
            anomalies=anomalies,
        )

    def to_dict(self) -> dict[str, Any]:
        """Projection as a JSON-serializable dict (datetimes as ISO strings)."""
        return {
            "incident_id": self.incident_id,
            "scenario_id": self.scenario_id,
            "status": self.status,
            "start_time": _iso(self.start_time),
            "detection_time": _iso(self.detection_time),
            "investigation_time": _iso(self.investigation_time),
            "containment_start_time": _iso(self.containment_start_time),
            "containment_time": _iso(self.containment_time),
            "end_time": _iso(self.end_time),
            "containment_failures": self.containment_failures,
            "ttd_seconds": self.ttd_seconds,
            "ttc_seconds": self.ttc_seconds,
            "outcome": self.outcome,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "IncidentProjection":
        """Rebuild a projection from a stored projection dict (read path)."""
        def _dt(key: str) -> Optional[datetime]:
            raw = data.get(key)
            return datetime.fromisoformat(raw) if raw else None

        return cls(
            incident_id=data["incident_id"],
            scenario_id=data.get("scenario_id"),
            status=data["status"],
            start_time=_dt("start_time"),
            detection_time=_dt("detection_time"),
            investigation_time=_dt("investigation_time"),
            containment_start_time=_dt("containment_start_time"),
            containment_time=_dt("containment_time"),
            end_time=_dt("end_time"),
            containment_failures=data["containment_failures"],
            ttd_seconds=data.get("ttd_seconds"),
            ttc_seconds=data.get("ttc_seconds"),
            outcome=data["outcome"],
        )
