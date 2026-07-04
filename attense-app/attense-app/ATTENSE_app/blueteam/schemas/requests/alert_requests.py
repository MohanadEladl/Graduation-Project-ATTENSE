"""
alert_requests.py — Alert Request Schemas
==========================================
Pydantic models for alert-related API endpoints.
These enforce the input shape — invalid requests die at the gate.
"""

from __future__ import annotations
from pydantic import BaseModel, Field


class _IncidentContext(BaseModel):
    """Shared fields required by every endpoint."""
    incident_id: str = Field(..., description="Unique identifier of the incident.", examples=["inc-2024-001"])
    scenario_id: str = Field(..., description="Scenario this incident belongs to.", examples=["scenario-xss-01"])


class RaiseAlertRequest(_IncidentContext):
    """Payload for POST /blueteam/raise-alert (SIEM raises alert)."""
    siem_id: str = Field(default="wazuh-manager", description="Identifier of the SIEM system.")
    target_id: str = Field(..., description="ID of the resource that triggered the alert.")
    target_type: str = Field(default="host", description="Type: host | service | account.")
    rule_name: str | None = Field(default=None, description="Detection rule that fired.", examples=["web_brute_force"])
    severity: str = Field(default="high", description="Alert severity.", examples=["low", "medium", "high", "critical"])
    raw_log: str | None = Field(default=None, description="Raw log line that triggered the rule.")


class InvestigateAlertRequest(_IncidentContext):
    """Payload for POST /blueteam/investigate-alert (analyst starts triage)."""
    analyst_id: str = Field(..., description="ID of the analyst.", examples=["analyst-42"])
    alert_id: str = Field(..., description="ID of the alert being investigated.", examples=["alert-9921"])
    notes: str | None = Field(default=None, description="Optional triage notes.")


class DenyAlertRequest(_IncidentContext):
    """Payload for POST /blueteam/deny-alert (analyst marks false positive)."""
    analyst_id: str = Field(..., description="ID of the analyst denying the alert.")
    alert_id: str = Field(..., description="ID of the alert being denied.")
    notes: str | None = Field(default=None, description="Reason for denial.")
