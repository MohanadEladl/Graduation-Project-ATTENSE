import logging
import os
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from attense_core.models.standard_event import StandardEvent
from dependencies.auth import require_events_secret, require_session
from core.report_helpers import scored_report as _scored_report


logger = logging.getLogger("attense-controller")

router = APIRouter(prefix="/api/incidents")

ACTIONS_DIR = os.environ.get("ACTIONS_LOG_DIR", "/attense/actions")

def _serialize_report(report: dict) -> dict:
    """Convert timedelta fields to seconds so FastAPI can serialize to JSON."""
    out = {}
    for k, v in report.items():
        if isinstance(v, timedelta):
            out[k] = v.total_seconds()
        elif isinstance(v, dict):
            out[k] = _serialize_report(v)
        elif isinstance(v, list):
            out[k] = [_serialize_report(i) if isinstance(i, dict) else (i.total_seconds() if isinstance(i, timedelta) else i) for i in v]
        else:
            out[k] = v
    return out


def _check_room_closed(incident_id: str) -> None:
    """Raise 425 if the room for this incident is still in progress."""
    from core.room_manager import find_room_for_incident
    room = find_room_for_incident(incident_id)
    if room is not None and room.get("status") != "closed":
        raise HTTPException(
            status_code=425,
            detail="Report not yet available — the exercise is still in progress.",
        )


@router.post("/events", status_code=202)
def ingest_event(
    body: StandardEvent,
    _auth: None = Depends(require_events_secret),
):
    """
    The single validated event-ingestion endpoint (report Phase 2). The body is
    the canonical `StandardEvent` contract -- enum-validated, UTC-aware -- so a
    malformed event is rejected here with 422 instead of being accepted (202)
    and then failing silently inside process_event(). The legacy `timestamp`
    field is still accepted as an alias for `occurred_at`, so the red-team
    engine's existing payload keeps working.

    Service-to-service producers (e.g. the red-team engine emitting
    malicious_action_executed) POST here; the event is adapted down to the
    legacy `Event` and fed to the same controller.process_event() the
    signal-store -> mapped_events.jsonl file-tail path uses -- the red-team
    containers have no access to attense-app's data volume.
    """
    from main import controller
    from attense_core.models.constants import EventType
    from core import room_manager

    controller.process_event(body.to_legacy_event_dict())

    # Auto-surface a Blue Team room only once the red-team learner has
    # explicitly finished their mission (event_type "mission_finished"),
    # not on the first attack event - so Blue Team sees nothing about this
    # exercise until it's actually over. Attack events still land durably and
    # update the in-memory Incident projection the moment they happen (via
    # process_event above); only room creation/visibility is deferred. Best
    # effort: a failure here must never reject the event ingestion itself.
    if body.event_type == EventType.MISSION_FINISHED:
        try:
            incident = controller.incidents.get(body.incident_id)
            attack_started_at = None
            if incident is not None and incident.start_time is not None:
                start_time = incident.start_time
                attack_started_at = (
                    start_time.isoformat() if hasattr(start_time, "isoformat") else str(start_time)
                )
            room_manager.ensure_room_for_incident(
                body.incident_id, body.scenario_id, attack_started_at=attack_started_at
            )
        except Exception:
            logger.exception(
                "Auto-create room failed for incident %s", body.incident_id
            )

    return {"status": "accepted", "event_id": body.event_id}


@router.get("/")
def list_incidents(session: dict = Depends(require_session)):
    from main import controller

    return list(controller.incidents.keys())


@router.get("/{incident_id}")
def get_incident(incident_id: str, session: dict = Depends(require_session)):
    from main import controller

    incident = controller.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/report")
def get_incident_report(
    incident_id: str,
    session: dict = Depends(require_session),
):
    from main import controller

    _check_room_closed(incident_id)
    # After a restart the controller may not have this incident in memory (it
    # only replays mapped_events.jsonl). Pass None so _scored_report falls
    # through to run_bridge, which reads the event_store from disk.
    incident = controller.incidents.get(incident_id)
    try:
        report, _events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    return _serialize_report(report)


@router.get("/{incident_id}/report/markdown", response_class=PlainTextResponse)
def get_incident_report_markdown(
    incident_id: str,
    session: dict = Depends(require_session),
):
    from main import controller
    from pipeline.report_generator import generate

    _check_room_closed(incident_id)
    incident = controller.incidents.get(incident_id)
    # Serve the file written by _generate_final_reports on exercise close.
    pre_path = os.path.join(ACTIONS_DIR, f"{incident_id}_report.md")
    if os.path.exists(pre_path):
        with open(pre_path, encoding="utf-8") as fh:
            return fh.read()
    try:
        report, events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    return generate(report, events)


@router.get("/{incident_id}/report/member/{member_id}")
def get_member_report(
    incident_id: str,
    member_id: str,
    session: dict = Depends(require_session),
):
    from main import controller
    from pipeline.bridge import member_events

    _check_room_closed(incident_id)
    incident = controller.incidents.get(incident_id)
    try:
        report, events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    member_scores = report.get("member_scores", {})
    if member_id not in member_scores:
        raise HTTPException(status_code=404, detail=f"No report for analyst '{member_id}'")
    member_report = {**report, **member_scores[member_id]}
    member_report["member_scores"] = {}
    member_report["analyst_timeline"] = [
        {"actor_id": e.actor_id, "event_type": e.event_type,
         "timestamp": e.timestamp.isoformat() if e.timestamp else None}
        for e in member_events(member_id, events)
        if e.actor_type == "blue_team"
    ]
    return _serialize_report(member_report)


@router.get("/{incident_id}/report/member/{member_id}/markdown", response_class=PlainTextResponse)
def get_member_report_markdown(
    incident_id: str,
    member_id: str,
    session: dict = Depends(require_session),
):
    from main import controller
    from pipeline.bridge import member_events
    from pipeline.report_generator import generate

    _check_room_closed(incident_id)
    incident = controller.incidents.get(incident_id)
    # Serve the file written by _generate_final_reports on exercise close.
    safe_id = member_id.replace("/", "-").replace("\\", "-")
    pre_path = os.path.join(ACTIONS_DIR, f"{incident_id}_{safe_id}_report.md")
    if os.path.exists(pre_path):
        with open(pre_path, encoding="utf-8") as fh:
            return fh.read()
    try:
        report, events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    member_scores = report.get("member_scores", {})
    if member_id not in member_scores:
        raise HTTPException(status_code=404, detail=f"No report for analyst '{member_id}'")
    member_report = {**report, **member_scores[member_id]}
    member_report["member_scores"] = {}
    return generate(member_report, member_events(member_id, events), member_id=member_id)


_WORD_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


@router.get("/{incident_id}/report/word")
def get_incident_report_word(
    incident_id: str,
    session: dict = Depends(require_session),
):
    from pipeline.word_generator import generate_word

    _check_room_closed(incident_id)
    from main import controller
    incident = controller.incidents.get(incident_id)
    try:
        report, _events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    docx_bytes = generate_word(_serialize_report(report))
    filename = f"incident_report_{incident_id[:8]}.docx"
    return Response(
        content=docx_bytes,
        media_type=_WORD_MIME,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{incident_id}/report/member/{member_id}/word")
def get_member_report_word(
    incident_id: str,
    member_id: str,
    session: dict = Depends(require_session),
):
    from pipeline.word_generator import generate_word

    _check_room_closed(incident_id)
    from main import controller
    incident = controller.incidents.get(incident_id)
    try:
        report, _events = _scored_report(incident_id, incident)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="No event data for this incident") from exc
    member_scores = report.get("member_scores", {})
    if member_id not in member_scores:
        raise HTTPException(status_code=404, detail=f"No report for analyst '{member_id}'")
    member_report = {**report, **member_scores[member_id]}
    member_report["member_scores"] = {}
    docx_bytes = generate_word(_serialize_report(member_report), member_id=member_id)
    safe_id = member_id.replace("@", "_").replace(".", "_")
    filename = f"incident_report_{incident_id[:8]}_{safe_id}.docx"
    return Response(
        content=docx_bytes,
        media_type=_WORD_MIME,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

