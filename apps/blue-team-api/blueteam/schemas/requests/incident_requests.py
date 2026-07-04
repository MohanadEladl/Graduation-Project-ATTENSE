"""
incident_requests.py — Incident Request Schemas
================================================
Pydantic model for incident confirmation endpoint.
"""

from __future__ import annotations
from pydantic import BaseModel, Field


class ConfirmIncidentRequest(BaseModel):
    """Payload for POST /blueteam/confirm-incident (analyst confirms true positive)."""
    incident_id: str = Field(..., description="Unique identifier of the incident.")
    scenario_id: str = Field(..., description="Scenario this incident belongs to.")
    analyst_id: str = Field(..., description="ID of the analyst confirming the incident.")
    alert_id: str = Field(..., description="ID of the alert being confirmed.")
    severity: str = Field(default="high", description="Assessed severity.", examples=["low", "medium", "high", "critical"])
    notes: str | None = Field(default=None, description="Optional analyst notes / evidence summary.")
