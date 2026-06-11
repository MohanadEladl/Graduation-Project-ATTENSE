"""
response_coordinator.py — Blue Team Response Coordinator
==========================================================
Orchestrates the complete Blue Team incident response lifecycle.

Acts as a high-level coordinator that sequences the steps:
    raise_alert → investigate_alert → [deny | confirm → initiate → complete]

Used for automated / scripted scenarios where the full flow runs without
interactive analyst input (e.g. AI-driven responses, integration tests).

For interactive (human) flows, each step is triggered individually via router.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from infrastructure.eventstore.event_emitter import EventEmitter
from infrastructure.thehive.hive_client import HiveClient
from infrastructure.sandbox.target_connector import TargetConnector

logger = logging.getLogger(__name__)


@dataclass
class ContainmentPlan:
    """Describes how to contain a specific attack on a specific target."""
    analyst_id: str
    target_id: str
    target_type: str
    strategy: str
    notes: str | None = None


class ResponseCoordinator:
    """
    Coordinates the full incident response lifecycle.

    Attributes
    ----------
    emitter : EventEmitter
        Shared event store wrapper — all events are published here.
    hive    : HiveClient
        Hive integration for case management updates.
    sandbox : TargetConnector
        Sandbox connector for executing containment actions.
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
        plan: ContainmentPlan,
        severity: str = "high",
    ) -> dict:
        """
        Execute a full automated incident response sequence.

        Steps:
            1. Investigate alert
            2. Confirm incident
            3. Initiate containment
            4. Complete containment

        Returns a summary dict with all event IDs and final incident status.
        """
        from core.services.alert_service import investigate_alert, deny_alert
        from core.services.incident_service import confirm_incident
        from core.services.containment_service import initiate_containment, complete_containment
        from schemas.requests.alert_requests import InvestigateAlertRequest
        from schemas.requests.incident_requests import ConfirmIncidentRequest
        from schemas.requests.containment_requests import (
            InitiateContainmentRequest,
            CompleteContainmentRequest,
        )

        logger.info(
            "[ResponseCoordinator] Starting automated response for incident '%s'.",
            incident_id,
        )

        r1 = investigate_alert(
            body=InvestigateAlertRequest(
                incident_id=incident_id, scenario_id=scenario_id,
                analyst_id=analyst_id, alert_id=alert_id,
            ),
            emitter=self.emitter,
        )
        r2 = confirm_incident(
            body=ConfirmIncidentRequest(
                incident_id=incident_id, scenario_id=scenario_id,
                analyst_id=analyst_id, alert_id=alert_id, severity=severity,
            ),
            emitter=self.emitter,
            hive=self.hive,
        )
        r3 = initiate_containment(
            body=InitiateContainmentRequest(
                incident_id=incident_id, scenario_id=scenario_id,
                analyst_id=plan.analyst_id, target_id=plan.target_id,
                target_type=plan.target_type, strategy=plan.strategy,
            ),
            emitter=self.emitter,
            sandbox=self.sandbox,
        )
        r4 = complete_containment(
            body=CompleteContainmentRequest(
                incident_id=incident_id, scenario_id=scenario_id,
                analyst_id=plan.analyst_id, target_id=plan.target_id,
                target_type=plan.target_type, notes=plan.notes,
            ),
            emitter=self.emitter,
        )

        logger.info(
            "[ResponseCoordinator] Automated response complete for incident '%s'. "
            "Final status: %s",
            incident_id, r4.incident_status,
        )

        return {
            "incident_id": incident_id,
            "final_status": r4.incident_status,
            "events": [r1.event_id, r2.event_id, r3.event_id, r4.event_id],
        }
