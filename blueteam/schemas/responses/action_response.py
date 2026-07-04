"""
action_response.py — Standard API Response Envelope
=====================================================
Returned by every Blue Team endpoint.
Provides a consistent response shape regardless of which action was taken.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from ATTENSE_app.incidents.incident import Incident
from ATTENSE_app.events.event import Event


class ActionResponse(BaseModel):
    """Standard envelope returned by every Blue Team / System endpoint."""

    ok: bool = Field(..., description="True if the action succeeded.")
    incident_id: str = Field(..., description="Incident the action was applied to.")
    event_id: str = Field(..., description="ID of the event that was created.")
    event_type: str = Field(..., description="Type of the event that was created.")
    incident_status: str = Field(..., description="Incident status after this action.")
    timestamp: str = Field(..., description="ISO-8601 timestamp of the event.")
    message: str = Field(default="", description="Human-readable result message.")
    enrichment: dict | None = Field(
        default=None,
        description=(
            "Cortex-Lite threat intelligence enrichment. "
            "Present on alert_raised events only. "
            "None when enrichment is disabled or no IOCs were found."
        ),
    )

    @classmethod
    def from_event(
        cls,
        incident: Incident,
        event: Event,
        message: str = "",
        enrichment: dict | None = None,
    ) -> "ActionResponse":
        """
        Factory method to build a response from an incident + event pair.

        Parameters
        ----------
        incident    : The incident after applying the event.
        event       : The event that was just created and stored.
        message     : Optional human-readable summary message.
        enrichment  : Optional Cortex-Lite threat intelligence report dict.
        """
        return cls(
            ok=True,
            incident_id=incident.incident_id,
            event_id=event.event_id,
            event_type=event.event_type,
            incident_status=incident.status,
            timestamp=event.timestamp.isoformat(),
            message=message,
            enrichment=enrichment,
        )
