"""The canonical ATTENSE event contract.

Phase 2 of ATTENSE_Refactoring_Optimization_Report.md. `StandardEvent` is the
single validated event format every producer (red-team engine, Wazuh signal
mapper, blue-team) is adapted into, and the format the one HTTP ingest endpoint
validates. It replaces the hand-written `event.schema.json` (which had drifted
out of sync with the Python model) as the schema authority — the JSON Schema is
now generated *from* this model (`scripts/generate_event_schema.py`).

What it adds over the legacy `attense_core.models.event.Event`:
  - typed enums for event/actor/target/outcome (see `constants.py`);
  - `schema_version` and `source` (which component emitted it);
  - `room_id` / `run_id` correlation fields (tenancy + repeated runs);
  - `occurred_at` that is **timezone-aware UTC** — naive timestamps are
    rejected, not silently stored (the legacy `Event` accepted naive `now()`).

It is deliberately additive: the legacy `Event` and the incident state machine
are untouched. `to_legacy_event()` bridges a validated `StandardEvent` back into
the existing `Event` (folding the new fields into `metadata` so nothing is lost),
so the Phase 1 characterization behaviour is preserved until Phase 3 swaps the
storage/projection layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from attense_core.models.constants import (
    ActorType,
    EventSource,
    EventType,
    Outcome,
    TargetType,
)
from attense_core.models.event import Event

SCHEMA_VERSION = "1.0"


class StandardEvent(BaseModel):
    """One validated ATTENSE event. See module docstring."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    schema_version: str = Field(default=SCHEMA_VERSION)
    event_id: str
    incident_id: str
    room_id: Optional[str] = None
    run_id: Optional[str] = None
    # External system id (e.g. a Wazuh alert id) kept SEPARATE from incident_id,
    # so a detection signal correlates to the exercise incident instead of
    # minting its own (report Phase 4: "Store external IDs separately").
    source_event_id: Optional[str] = None
    scenario_id: str
    source: EventSource = EventSource.UNKNOWN
    actor_id: str
    actor_type: ActorType
    target_id: str
    target_type: TargetType
    event_type: EventType
    occurred_at: datetime
    outcome: Optional[Outcome] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ── Normalization ───────────────────────────────────────────────────────
    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_timestamp(cls, data: Any) -> Any:
        """Accept the legacy `timestamp` field as an alias for `occurred_at`,
        and default a missing/None time to now (UTC). Producers that already
        send `occurred_at` are unaffected."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "occurred_at" not in data or data.get("occurred_at") is None:
            if data.get("timestamp") is not None:
                data["occurred_at"] = data["timestamp"]
            else:
                data["occurred_at"] = datetime.now(timezone.utc)
        data.pop("timestamp", None)

        # Promote correlation/contract fields that the legacy bridge folds into
        # metadata back to top level, so an event that crossed the legacy Event
        # boundary (or a producer that only sets them in metadata) round-trips.
        metadata = data.get("metadata") or {}
        if isinstance(metadata, dict):
            for key in (
                "source",
                "schema_version",
                "room_id",
                "run_id",
                "source_event_id",
            ):
                if data.get(key) is None and key in metadata:
                    data[key] = metadata[key]
        return data

    @field_validator("metadata", mode="before")
    @classmethod
    def _default_metadata(cls, value: Any) -> Any:
        """Accept an explicit `null` metadata (legacy producers sent it) as {}."""
        return {} if value is None else value

    @field_validator("occurred_at", mode="before")
    @classmethod
    def _require_utc_aware(cls, value: Any) -> datetime:
        """Reject naive timestamps; normalize aware ones to UTC."""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(
                    "occurred_at must be an ISO 8601 datetime string"
                ) from exc
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError(
                    "occurred_at must be timezone-aware UTC; naive datetimes "
                    "are rejected (legacy behaviour stored naive now())"
                )
            return value.astimezone(timezone.utc)
        raise ValueError("occurred_at must be a datetime or ISO 8601 string")

    # ── Bridge to the legacy Event / incident state machine ──────────────────
    def _legacy_metadata(self) -> dict[str, Any]:
        """Carry the new contract fields into the legacy Event.metadata so the
        correlation IDs / source / version survive the adapt-down (without
        clobbering any caller-provided metadata key)."""
        md = dict(self.metadata or {})
        for key, val in (
            ("schema_version", self.schema_version),
            ("source", self.source.value),
            ("room_id", self.room_id),
            ("run_id", self.run_id),
            ("source_event_id", self.source_event_id),
        ):
            if val is not None:
                md.setdefault(key, val)
        return md

    def to_legacy_event(self) -> Event:
        """Build the legacy `Event` the incident state machine consumes.
        Enum values become their string literals; `occurred_at` (aware) is
        passed straight through (Event accepts a datetime as-is)."""
        return Event(
            event_id=self.event_id,
            incident_id=self.incident_id,
            scenario_id=self.scenario_id,
            actor_id=self.actor_id,
            target_id=self.target_id,
            event_type=self.event_type.value,
            actor_type=self.actor_type.value,
            target_type=self.target_type.value,
            timestamp=self.occurred_at,
            outcome=self.outcome.value if self.outcome is not None else None,
            metadata=self._legacy_metadata(),
        )

    def to_legacy_event_dict(self) -> dict[str, Any]:
        """The legacy `Event.to_dict()` shape, for `controller.process_event()`."""
        return self.to_legacy_event().to_dict()

    # ── Producer adapters (report Phase 2, step 4) ───────────────────────────
    @classmethod
    def from_ingest_payload(cls, payload: dict[str, Any]) -> "StandardEvent":
        """Validate an arbitrary inbound payload (the HTTP ingest path)."""
        return cls.model_validate(payload)

    @classmethod
    def from_legacy_event(
        cls,
        event: Any,
        *,
        source: EventSource,
        room_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> "StandardEvent":
        """Lift an in-process legacy `Event` (or its dict) into a StandardEvent,
        stamping the producing `source` and optional correlation IDs. Used by
        the Wazuh mapper and blue-team, which build `Event` objects directly."""
        payload = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        payload["source"] = source.value if isinstance(source, EventSource) else source
        if room_id is not None:
            payload["room_id"] = room_id
        if run_id is not None:
            payload["run_id"] = run_id
        return cls.model_validate(payload)

    @classmethod
    def from_redteam_payload(cls, payload: dict[str, Any]) -> "StandardEvent":
        """Adapter for the red-team engine's malicious_action_executed POST."""
        data = dict(payload)
        data.setdefault("source", EventSource.RED_TEAM.value)
        return cls.model_validate(data)

    @classmethod
    def from_wazuh_event(cls, event: Any, **kwargs: Any) -> "StandardEvent":
        """Adapter for the Wazuh signal mapper's alert_raised Event."""
        return cls.from_legacy_event(event, source=EventSource.SIGNAL_STORE, **kwargs)

    @classmethod
    def from_blueteam_event(cls, event: Any, **kwargs: Any) -> "StandardEvent":
        """Adapter for blue-team investigation/containment Events."""
        return cls.from_legacy_event(event, source=EventSource.BLUE_TEAM, **kwargs)
