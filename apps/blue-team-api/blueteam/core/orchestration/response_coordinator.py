"""
response_coordinator.py - Blue Team Response Coordinator
========================================================
Orchestrates the non-containment Blue Team incident response lifecycle.

Acts as a high-level coordinator that sequences triage steps:
    raise_alert -> investigate_alert -> [deny | confirm]

Containment is intentionally excluded from automation. ATTENSE measures the
analyst's selected response action, so blocking/isolation actions must be
chosen and triggered by the analyst through the UI/API/TheHive responder flow.

For interactive human flows, each step is triggered individually via router.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ...infrastructure.eventstore.event_emitter import EventEmitter
from ...infrastructure.thehive.hive_client import HiveClient
from ...infrastructure.sandbox.target_connector import TargetConnector

logger = logging.getLogger(__name__)


@dataclass
class ContainmentPlan:
    """Describes a possible containment option for a specific target."""

    analyst_id: str
    target_id: str
    target_type: str
    strategy: str
    notes: str | None = None


class ResponseCoordinator:
    """
    Coordinates the non-containment incident response lifecycle.

    Attributes
    ----------
    emitter : EventEmitter
        Shared event store wrapper; all events are published here.
    hive    : HiveClient
        Hive integration for case management updates.
    sandbox : TargetConnector
        Sandbox connector retained for interactive containment endpoints.
    """

    def __init__(
        self,
        emitter: EventEmitter,
        hive: HiveClient,
        sandbox: TargetConnector,
    ) -> None:
        self.emitter = emitter
        self.hive = hive
        self.sandbox = sandbox

    def run_automated_response(
        self,
        incident_id: str,
        scenario_id: str,
        analyst_id: str,
        alert_id: str,
        room_id: str,
        plan: ContainmentPlan,
        severity: str = "high",
    ) -> dict:
        """
        Execute only the automated triage sequence.

        Steps:
            1. Investigate alert.
            2. Confirm incident.
            3. Stop and wait for analyst-selected containment.

        This method does not initiate or complete containment. Measuring
        containment is only meaningful when the analyst chooses the action.
        Returns a summary dict with event IDs and current incident status.
        """
        from ..services.alert_service import investigate_alert
        from ..services.incident_service import confirm_incident
        from ...schemas.requests.alert_requests import InvestigateAlertRequest
        from ...schemas.requests.incident_requests import ConfirmIncidentRequest

        logger.info(
            "[ResponseCoordinator] Starting automated triage for incident '%s'.",
            incident_id,
        )

        r1 = investigate_alert(
            body=InvestigateAlertRequest(
                incident_id=incident_id,
                scenario_id=scenario_id,
                analyst_id=analyst_id,
                alert_id=alert_id,
            ),
            emitter=self.emitter,
            room_id=room_id,
        )
        r2 = confirm_incident(
            body=ConfirmIncidentRequest(
                incident_id=incident_id,
                scenario_id=scenario_id,
                analyst_id=analyst_id,
                alert_id=alert_id,
                severity=severity,
            ),
            emitter=self.emitter,
            hive=self.hive,
            room_id=room_id,
        )

        logger.info(
            "[ResponseCoordinator] Automated triage complete for incident '%s'. "
            "Awaiting analyst containment choice. Current status: %s",
            incident_id,
            r2.incident_status,
        )

        return {
            "incident_id": incident_id,
            "current_status": r2.incident_status,
            "awaiting": "analyst_containment_choice",
            "containment_plan": {
                "target_id": plan.target_id,
                "target_type": plan.target_type,
                "strategy": plan.strategy,
                "notes": plan.notes,
            },
            "events": [r1.event_id, r2.event_id],
        }
