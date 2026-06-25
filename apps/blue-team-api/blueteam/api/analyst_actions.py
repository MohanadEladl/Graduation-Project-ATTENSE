"""
routers/analyst_actions.py — Analyst Action Endpoints
======================================================
Receives structured SOC actions from the Watcher Agent running on each
analyst machine and stores them for scoring / replay.

Storage layout
--------------
Each analyst gets their own daily JSONL file:
  /attense/actions/<analyst_id>_<YYYY-MM-DD>.jsonl

Files older than 7 days are deleted automatically on startup.

Endpoints
---------
POST /blueteam/analyst-action
    Watcher Agent posts one classified action at a time.

GET  /blueteam/analyst-actions/{incident_id}
    Returns all analyst actions for an incident, ordered by t_offset_sec.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blueteam", tags=["Analyst Actions"])

# ── Directory config ──────────────────────────────────────────────────────────
ACTIONS_DIR = os.environ.get("ACTIONS_LOG_DIR", "/attense/actions")


def get_analyst_log_path(analyst_id: str) -> str:
    """Each analyst gets their own daily log file."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_id  = analyst_id.replace("/", "-").replace("\\", "-")
    return os.path.join(ACTIONS_DIR, f"{safe_id}_{date_str}.jsonl")


# ── 7-day auto-cleanup ────────────────────────────────────────────────────────

def cleanup_old_logs(retention_days: int = 7) -> None:
    """Delete analyst log files older than retention_days."""
    cutoff  = datetime.now(timezone.utc) - timedelta(days=retention_days)
    pattern = os.path.join(ACTIONS_DIR, "*.jsonl")
    for path in glob.glob(pattern):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
            if mtime < cutoff:
                os.remove(path)
                logger.info("[analyst-action] Deleted old log: %s", path)
        except OSError as exc:
            logger.warning("[analyst-action] Could not delete %s: %s", path, exc)


# ── Per-analyst JSONL persistence ────────────────────────────────────────────

def _append_to_disk(record: dict) -> None:
    path = get_analyst_log_path(record["analyst_id"])
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("[analyst-action] Could not write to %s: %s", path, exc)


def _load_from_disk() -> defaultdict[str, List[dict]]:
    """
    Read all analyst log files from today and populate the in-memory store.
    Keyed by incident_id so GET /analyst-actions/{incident_id} works correctly.
    """
    store: defaultdict[str, List[dict]] = defaultdict(list)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pattern  = os.path.join(ACTIONS_DIR, f"*_{date_str}.jsonl")
    total    = 0
    for path in glob.glob(pattern):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        store[rec["incident_id"]].append(rec)
                        total += 1
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[analyst-action] Could not load %s: %s", path, exc)
    if total:
        logger.info("[analyst-action] Loaded %d records from today's log files", total)
    return store


# ── In-memory store  (incident_id → list of action dicts) ────────────────────
_actions: defaultdict[str, List[dict]] = _load_from_disk()


# ── Enums / Models ────────────────────────────────────────────────────────────

class AnalystEventType(str, Enum):
    investigation_started    = "investigation_started"
    incident_confirmed       = "incident_confirmed"
    containment_initiated    = "containment_initiated"
    containment_succeeded    = "containment_succeeded"
    incident_ended           = "incident_ended"
    alert_denied             = "alert_denied"
    # v2.0.0 — post-containment events (3 from watcher, 2 from TheHive webhook)
    evidence_preserved       = "evidence_preserved"
    eradication_completed    = "eradication_completed"
    recovery_validated       = "recovery_validated"
    dismissal_approved       = "dismissal_approved"
    lessons_learned_recorded = "lessons_learned_recorded"


class AnalystActionRequest(BaseModel):
    analyst_id:     str              = Field(..., description="Analyst identifier, e.g. analyst-alice")
    incident_id:    str              = Field(..., description="Incident this action belongs to")
    scenario_id:    str              = Field(..., description="Scenario ID, e.g. APP-02")
    event_type:     AnalystEventType = Field(..., description="Classified SOC action type")
    t_offset_sec:   int              = Field(..., description="Seconds since session start")
    detail:         str              = Field(..., description="One-sentence description of the action")
    timestamp:      Optional[float]  = Field(default=None, description="Unix epoch; defaults to now")


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
    record = _persist(body)
    return AnalystActionResponse(ok=True, **record)


def _persist(body: AnalystActionRequest) -> dict:
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
    _append_to_disk(record)

    logger.info(
        "[analyst-action] analyst=%s  incident=%s  event_type=%s  t_offset=%ds",
        body.analyst_id, body.incident_id, body.event_type.value, body.t_offset_sec,
    )
    return record


def store_analyst_action(action: dict) -> dict:
    """
    Store an analyst action dict produced by analyst_action_extractor.py
    (Hive webhook → analyst action).

    CALLER CONTRACT — self-approval guard:
    If action["event_type"] == "dismissal_approved", the caller (webhook_router)
    MUST call _check_dismissal_approval() against the EventStore BEFORE calling
    this function. This function has no access to the event store and cannot
    enforce the second-actor requirement itself. Bypassing the guard here
    re-opens the self-approval loophole via the extractor path.
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
    actions = sorted(
        _actions.get(incident_id, []),
        key=lambda a: a["t_offset_sec"],
    )
    return AnalystActionsListResponse(
        incident_id=incident_id,
        count=len(actions),
        actions=actions,
    )
