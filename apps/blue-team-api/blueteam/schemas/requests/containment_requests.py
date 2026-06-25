"""
containment_requests.py — Containment Request Schemas
=======================================================
Pydantic models for containment endpoints.
"""

from __future__ import annotations
from pydantic import BaseModel, Field


class InitiateContainmentRequest(BaseModel):
    """Payload for POST /blueteam/initiate-containment."""
    incident_id: str = Field(..., description="Unique identifier of the incident.")
    scenario_id: str = Field(..., description="Scenario this incident belongs to.")
    analyst_id: str = Field(..., description="ID of the analyst initiating containment.")
    target_id: str = Field(..., description="ID of the resource to contain.", examples=["host-web01"])
    target_type: str = Field(default="host", description="Type: host | service | account.")
    strategy: str | None = Field(
        default=None,
        description="Containment strategy.",
        examples=["kill_process", "block_request", "lock_account", "block_path", "isolate_host"],
    )


class CompleteContainmentRequest(BaseModel):
    """Payload for POST /blueteam/complete-containment."""
    incident_id: str = Field(..., description="Unique identifier of the incident.")
    scenario_id: str = Field(..., description="Scenario this incident belongs to.")
    analyst_id: str = Field(..., description="ID of the analyst completing containment.")
    target_id: str = Field(..., description="ID of the resource that was contained.")
    target_type: str = Field(default="host", description="Type of the contained resource.")
    notes: str | None = Field(default=None, description="Optional post-action notes.")
