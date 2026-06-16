"""
routers/analyst_actions.py — Analyst Action Endpoints
======================================================
Receives structured SOC actions from the Watcher Agent running on each
analyst machine and stores them for scoring / replay.

Endpoints
---------
POST /blueteam/analyst-action
    Watcher Agent posts one classified action at a time.

GET  /blueteam/analyst-actions/{incident_id}
    Returns all analyst actions for an incident, ordered by t_offset_sec.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from enum import Enum
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blueteam", tags=["Analyst Actions"])

# ── In-memory store  (incident_id → list of action dicts) ────────────────────
# Keyed by incident_id; each value is a list ordered by insertion.
# GET endpoint re-sorts by t_offset_sec before returning.
_actions: defaultdict[str, List[dict]] = defaultdict(list)


# ── Enums / Models ────────────────────────────────────────────────────────────

class AnalystEventType(str, Enum):
    investigation_started   = "investigation_started"
    incident_confirmed      = "incident_confirmed"
    containment_initiated   = "containment_initiated"
    containment_succeeded   = "containment_succeeded"
    incident_ended          = "incident_ended"
    alert_denied            = "alert_denied"


class AnalystActionRequest(BaseModel):
    analyst_id:     str           = Field(..., description="Analyst identifier, e.g. analyst-alice")
    incident_id:    str           = Field(..., description="Incident this action belongs to")
    scenario_id:    str           = Field(..., description="Scenario ID, e.g. APP-02")
    event_type:     AnalystEventType = Field(..., description="Classified SOC action type")
    t_offset_sec:   int           = Field(..., description="Seconds since session start when the action occurred")
    detail:         str           = Field(..., description="One-sentence description of the action")
    timestamp:      Optional[float] = Field(default=None, description="Unix epoch when recorded; defaults to now")


class AnalystActionResponse(BaseModel):
    ok:             bool
    analyst_id:     str
    incident_id:    str
    scenario_id:    str
    event_type:     str
    t_offset_sec:   int
    detail:         str
    timestamp:      float
    stored_at:      float


class AnalystActionsListResponse(BaseModel):
    incident_id:    str
    count:          int
    actions:        List[dict]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/analyst-action",
    response_model=AnalystActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Watcher Agent posts a classified analyst action",
)
def record_analyst_action(body: AnalystActionRequest) -> AnalystActionResponse:
    """
    Stores a single classified SOC action emitted by the Watcher Agent.

    The Watcher Agent runs on the analyst machine, monitors auditd EXECVE
    events, and uses an LLM to classify significant SOC actions. Each
    classified event is posted here so ATTENSE can score analyst response
    time and technique.
    """
    record = _persist(body)
    return AnalystActionResponse(ok=True, **record)


def _persist(body: AnalystActionRequest) -> dict:
    """Build a stored record from a validated request and append it to the store."""
    stored_at = time.time()
    ts = body.timestamp if body.timestamp is not None else stored_at

    record = {
        "analyst_id":   body.analyst_id,
        "incident_id":  body.incident_id,
        "scenario_id":  body.scenario_id,
        "event_type":   body.event_type.value,
        "t_offset_sec": body.t_offset_sec,
        "detail":       body.detail,
        "timestamp":    ts,
        "stored_at":    stored_at,
    }

    _actions[body.incident_id].append(record)

    logger.info(
        "[analyst-action] analyst=%s  incident=%s  event_type=%s  t_offset=%ds",
        body.analyst_id, body.incident_id, body.event_type.value, body.t_offset_sec,
    )

    return record


def store_analyst_action(action: dict) -> dict:
    """
    Store an analyst action dict produced by analyst_action_extractor.py
    (Hive webhook → analyst action). Validates against AnalystActionRequest
    and appends to the same in-memory store used by the Watcher Agent endpoint.
    """
    body = AnalystActionRequest(**action)
    return _persist(body)


@router.get(
    "/analyst-actions/{incident_id}",
    response_model=AnalystActionsListResponse,
    status_code=status.HTTP_200_OK,
    summary="Return all analyst actions for an incident, ordered by t_offset_sec",
)
def list_analyst_actions(incident_id: str) -> AnalystActionsListResponse:
    """
    Returns every analyst action recorded for the given incident,
    sorted ascending by t_offset_sec (chronological order).
    """
    actions = sorted(
        _actions.get(incident_id, []),
        key=lambda a: a["t_offset_sec"],
    )
    return AnalystActionsListResponse(
        incident_id=incident_id,
        count=len(actions),
        actions=actions,
    )
