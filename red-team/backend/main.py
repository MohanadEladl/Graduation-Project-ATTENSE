"""
backend/main.py — FastAPI app for the ATTENSE educational cyber lab.

Endpoints:
  GET    /health                            – liveness
  GET    /api/modules                       – list all attack modules + metadata
  GET    /api/target                        – current default target
  POST   /api/sessions                      – create mission session
  GET    /api/sessions                      – list sessions
  GET    /api/sessions/{sid}                – session snapshot
  DELETE /api/sessions/{sid}                – close session
  POST   /api/sessions/{sid}/options        – set one option
  POST   /api/sessions/{sid}/target         – set target host/port
  POST   /api/sessions/{sid}/start          – begin mission (no attack)
  POST   /api/sessions/{sid}/execute        – execute the attack
  GET    /api/sessions/{sid}/logs           – full log history
  WS     /ws/sessions/{sid}                 – live log stream
  WS     /ws/shell                          – legacy single-tab shell

  Lab Mode (AttackBox):
  GET    /api/operator/attackbox/status      – AttackBox container status
  POST   /api/operator/attackbox/exec        – run command in AttackBox
  GET    /api/operator/attackbox/evidence     – tool command evidence
  GET    /api/operator/zap/status            – ZAP service status
  GET    /api/operator/zap/history           – ZAP proxy history
  POST   /api/operator/zap/repeater/send     – send request through ZAP

Modes:
  guided   – rich walkthrough; browser interactions count as evidence
  operator – AttackBox terminal/ZAP required; browser clicks do NOT count
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import json as _json

# Make sibling folders (core/, modules/, engine/) importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.module_loader import discover_modules    # noqa: E402
from backend.shell.router import ShellRouter       # noqa: E402
from backend.session_manager import SessionManager # noqa: E402
from backend.detections import DetectionBroker     # noqa: E402
from backend import operator_api                   # noqa: E402
from backend import action_trace                   # noqa: E402


DEFAULT_HOST = os.getenv("TARGET_HOST", "target-agent")
DEFAULT_PORT = int(os.getenv("TARGET_PORT", "80"))

# ── Watcher session store ─────────────────────────────────────────────────────
# Keyed by 6-character uppercase code. Plain dict — lifetime is the process.
import random
import string
import time as _time_mod

_WATCHER_SESSIONS: dict[str, dict] = {}


def _generate_code() -> str:
    """Return a random 6-character uppercase alphanumeric code."""
    alphabet = string.ascii_uppercase + string.digits
    while True:
        code = "".join(random.choices(alphabet, k=6))
        if code not in _WATCHER_SESSIONS:
            return code

app = FastAPI(
    title="ATTENSE Cyber Lab API",
    version="6.0.0",
    description="Backend API for the ATTENSE guided educational cyber range.",
)

# CORS — accept the React dev server and the nginx-served build
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # lab only
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single module registry shared across all connections (read-only)
_MODULES = discover_modules("modules")

# Process-wide session store. Each guided mission (one per browser workspace)
# owns a SessionRecord here; the legacy /ws/shell path is separate and uses
# ShellRouter.
_SESSIONS = SessionManager(_MODULES, DEFAULT_HOST, DEFAULT_PORT)

# Detection broker: polls signal-store, fans Wazuh alerts out to WS subscribers.
# Started on FastAPI startup so it runs inside the event loop.
_DETECTIONS = DetectionBroker()


@app.on_event("startup")
async def _boot() -> None:
    _DETECTIONS.start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await _DETECTIONS.stop()


# ── REST ──────────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "modules": len(_MODULES)}


@app.get("/api/modules")
def list_modules() -> list[dict]:
    """Return module metadata for the React sidebar."""
    out = []
    for m in sorted(_MODULES.values(), key=lambda x: x.module_id):
        out.append({
            "module_id":   m.module_id,
            "name":        m.name,
            "description": m.description,
            "category":    m.category.value,
            "scenario_id": m.scenario_id,
            "severity":    m.severity.value,
            "mitre":       getattr(m, "mitre", {}),
            "steps": getattr(m, "steps", []),
            # Lab guidance metadata — credentials_hint is stripped to avoid spoiling
            # the brute-force challenge via public API inspection.
            "lab":         {k: v for k, v in (getattr(m, "lab", {}) or {}).items()
                            if k != "credentials_hint"},
            "options": [
                {
                    "name":         o.name,
                    "display_name": o.display_name,
                    "description":  o.description,
                    "default":      str(o.default) if o.default not in ("", None) else "",
                    "required":     o.required,
                    "type":         o.option_type,
                }
                for o in m.options()
            ],
        })
    return out


@app.get("/api/target")
def get_target() -> dict:
    return {"host": DEFAULT_HOST, "port": DEFAULT_PORT}


# ── Guided-mission sessions ───────────────────────────────────────────────────
class CreateSessionBody(BaseModel):
    module_id: str
    mode: Optional[str] = "tutorial"
    mutation_mode: Optional[bool] = False
    mutation_intensity: Optional[str] = "single"


class SetOptionBody(BaseModel):
    key: str
    value: str


class SetTargetBody(BaseModel):
    host: str
    port: Optional[int] = None


def _require_session(sid: str):
    rec = _SESSIONS.get(sid)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown session: {sid}")
    return rec


@app.post("/api/sessions")
async def create_session(body: CreateSessionBody) -> dict:
    loop = asyncio.get_running_loop()
    mode = body.mode or "tutorial"
    try:
        rec = _SESSIONS.create(
            body.module_id,
            mode=mode,
            mutation_mode=bool(body.mutation_mode),
            mutation_intensity=body.mutation_intensity or "single",
            loop=loop,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return rec.snapshot()


@app.get("/api/sessions")
def list_sessions(module_id: Optional[str] = None) -> list[dict]:
    items = _SESSIONS.list()
    if module_id:
        items = [s for s in items if s.get("module_id") == module_id]
    return items


@app.get("/api/sessions/{sid}")
def get_session(sid: str) -> dict:
    return _require_session(sid).snapshot()


@app.delete("/api/sessions/{sid}")
def delete_session(sid: str) -> dict:
    ok = _SESSIONS.delete(sid)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Unknown session: {sid}")
    return {"ok": True}


@app.post("/api/sessions/{sid}/options")
def set_session_option(sid: str, body: SetOptionBody) -> dict:
    rec = _require_session(sid)
    _SESSIONS.set_option(rec, body.key, body.value)
    return rec.snapshot()


@app.post("/api/sessions/{sid}/target")
def set_session_target(sid: str, body: SetTargetBody) -> dict:
    rec = _require_session(sid)
    _SESSIONS.set_target(rec, body.host, body.port)
    return rec.snapshot()


@app.post("/api/sessions/{sid}/start")
async def start_session(sid: str) -> dict:
    """Begin guided mode — starts the timer + records mission_started_at.
    Does NOT execute the attack."""
    rec = _require_session(sid)
    if not rec.attack.timer.started_at:
        rec.attack.timer.start()
    if rec.mission_started_at is None:
        import time as _time
        rec.mission_started_at = _time.time()
    return rec.snapshot()


@app.post("/api/sessions/{sid}/check-progress")
async def check_progress(sid: str) -> dict:
    """Inspect target-agent evidence since mission start; do NOT run attack.

    Uses the mode and variant_id stored on the session:
      tutorial — all evidence counts toward task completion
      lab      — only evidence with via="attackbox" counts toward task completion
      variant_id — selects the specific attack flavour (replaces task ladder)

    Returns per-task completion + evidence cards + success state for the
    LearningPanel. Pure read — no side effects on the attack engine.
    """
    rec = _require_session(sid)
    started = rec.mission_started_at or rec.created_at
    mode = rec.mode
    variant_id = getattr(rec, "variant_id", None)
    from backend import lab_progress  # local import keeps cold-start fast
    result = lab_progress.compute(
        module_id=rec.module.module_id,
        mission_started_at=started,
        session_completed_steps=list(rec.completed_steps),
        mode=mode,
        variant_id=variant_id,
    )
    rec.update_learning_progress(result)
    _SESSIONS._persist()

    # If the mission just succeeded, push a preliminary skill score so the
    # radar graph is never empty even before a full report is generated.
    if result.get("success") and not rec.report_cache:
        try:
            from backend import skill_store as _skill_store
            _pct = int(result.get("progress_percent") or 0)
            _grade = "S" if _pct >= 90 else "A" if _pct >= 75 else "B" if _pct >= 55 else "C" if _pct >= 30 else "F"
            _vid = getattr(rec, "variant_id", None)
            _skill_store.update(rec.module.module_id, _vid, _pct, _grade)
        except Exception:
            pass

    return result


@app.get("/api/modules/{module_id}/variants")
async def list_module_variants(module_id: str) -> dict:
    """List the attack variants available for a given module.  Consumed by
    the variant-picker UI in the Workspace/Mission start screen."""
    from backend import lab_progress
    return {"module_id": module_id, "variants": lab_progress.list_variants(module_id)}


@app.post("/api/sessions/{sid}/variant")
async def set_session_variant(sid: str, body: dict) -> dict:
    """Set the active attack variant for a session.  Body: {variant_id: str}."""
    rec = _require_session(sid)
    variant_id = (body or {}).get("variant_id")
    rec.variant_id = variant_id
    return rec.snapshot()


# ─── Browser action tracing (Phase 2) ────────────────────────────────────────
@app.post("/api/lab/actions")
async def record_lab_action(body: dict) -> dict:
    """Record a single browser action emitted by the lab-browser overlay script.

    Expected body:
      { session_id, kind, selector?, text?, page?, extra? }
    """
    ev = action_trace.record(
        session_id=(body or {}).get("session_id"),
        kind=(body or {}).get("kind", "unknown"),
        selector=(body or {}).get("selector"),
        text=(body or {}).get("text"),
        page=(body or {}).get("page"),
        extra=(body or {}).get("extra"),
    )
    return {"ok": True, "id": ev["id"]}


@app.get("/api/sessions/{sid}/timeline")
async def get_session_timeline(sid: str) -> dict:
    """Unified timeline: browser actions + terminal commands + lab events,
    sorted chronologically.  Powers the Action Replay panel in the report."""
    rec = _require_session(sid)
    started = rec.mission_started_at or rec.created_at

    timeline: list[dict] = []

    # 1. Browser actions
    for a in action_trace.list_actions(session_id=sid, since=started, limit=1000):
        timeline.append({
            "ts":          a["ts"],
            "channel":     "browser",
            "kind":        a.get("kind", "action"),
            "summary":     _summarise_browser_action(a),
            "raw":         a,
        })

    # 2. Terminal commands from operator_api
    try:
        for c in operator_api.get_tool_evidence(since=started):
            timeline.append({
                "ts":          c.get("ts", 0.0),
                "channel":     "terminal",
                "kind":        c.get("tool", "tool_command"),
                "summary":     (c.get("command") or "")[:140],
                "raw":         c,
            })
    except Exception:
        pass

    # 3. Lab events from target-agent
    import urllib.request, urllib.error, json as _j
    target_url = os.getenv("LAB_EVENTS_URL", "http://target-agent")
    try:
        url = f"{target_url}/lab/events?since={started}&limit=500"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = _j.loads(resp.read().decode("utf-8"))
        for e in data.get("events", []):
            timeline.append({
                "ts":          e.get("ts", 0.0),
                "channel":     "evidence",
                "kind":        e.get("event_type"),
                "summary":     e.get("learner_message") or e.get("event_type"),
                "raw":         e,
            })
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        pass

    timeline.sort(key=lambda x: x.get("ts", 0.0))
    return {
        "session_id":         sid,
        "mission_started_at": started,
        "now":                __import__("time").time(),
        "timeline":           timeline,
        "counts": {
            "browser":  sum(1 for x in timeline if x["channel"] == "browser"),
            "terminal": sum(1 for x in timeline if x["channel"] == "terminal"),
            "evidence": sum(1 for x in timeline if x["channel"] == "evidence"),
        },
    }


def _summarise_browser_action(a: dict) -> str:
    """One-line human-readable summary for a browser-side action."""
    kind = a.get("kind", "action")
    sel  = a.get("selector") or ""
    txt  = (a.get("text") or "")[:60]
    page = a.get("page") or ""
    if kind == "page_view":
        return f"Viewed page {page}"
    if kind == "click":
        if txt:
            return f"Clicked \u201c{txt}\u201d ({sel})"
        return f"Clicked {sel}"
    if kind == "form_submit":
        return f"Submitted form on {page} ({sel})"
    if kind == "input_focus":
        return f"Focused input {sel}"
    return f"{kind} {sel}".strip()


@app.post("/api/sessions/{sid}/reset-evidence")
async def reset_evidence(sid: str) -> dict:
    """Reset a mission for a fresh attempt. Clears evidence, resets timer,
    learning state, and mission_started_at. Does NOT delete the session."""
    rec = _require_session(sid)
    import time as _time, urllib.request, urllib.error
    target_url = os.getenv("LAB_EVENTS_URL", "http://target-agent")
    try:
        req = urllib.request.Request(f"{target_url}/lab/events/reset", method="POST")
        urllib.request.urlopen(req, timeout=4).read()
    except (urllib.error.URLError, OSError):
        pass  # non-fatal; the mission_started_at reset still works
    rec.mission_started_at = _time.time()
    # Reset learning state for a fresh attempt
    rec.learning_state = "in_progress"
    rec.learning_completed_tasks = []
    rec.learning_progress_percent = 0
    rec.learning_success = False
    rec.learning_completed_at = None
    rec.latest_evidence = []
    rec.completed_steps = []
    # Restart the internal timer
    if rec.attack.timer.started_at:
        rec.attack.timer.started_at = _time.time()
    return rec.snapshot()


@app.post("/api/sessions/{sid}/restart")
async def restart_session(sid: str) -> dict:
    """Alias for reset-evidence — restarts the mission for a clean attempt."""
    return await reset_evidence(sid)


@app.get("/api/sessions/{sid}/report")
async def get_report(sid: str) -> dict:
    """Return (or generate) the post-mission coaching report for a session.

    The report combines:
      • lab_progress.compute() — task ladder + evidence cards
      • the unified timeline (browser + terminal + lab events)
      • the AI coaching agent (Claude Haiku, with rule-based fallback)
    and is cached on the session so repeat visits don't re-bill the LLM.
    """
    rec = _require_session(sid)
    if rec.report_cache:
        return rec.report_cache

    import urllib.request as _ur, urllib.error as _ue
    started = rec.mission_started_at or rec.created_at
    target_url = os.getenv("LAB_EVENTS_URL", "http://target-agent")

    # 1. Lab events
    events: list = []
    try:
        url = f"{target_url}/lab/events?since={started}&limit=500"
        with _ur.urlopen(url, timeout=4) as resp:
            events = __import__("json").loads(resp.read()).get("events", [])
    except (_ue.URLError, _ue.HTTPError, OSError):
        pass

    # 2. Unified timeline
    timeline_payload = await get_session_timeline(sid)
    timeline = timeline_payload.get("timeline", [])

    # 3. Progress for the active variant + mode
    from backend import lab_progress, report_agent
    progress = lab_progress.compute(
        module_id=rec.module.module_id,
        mission_started_at=started,
        session_completed_steps=list(rec.completed_steps),
        mode=rec.mode,
        variant_id=getattr(rec, "variant_id", None),
    )

    # 4. Hand it all to the agent
    report = report_agent.generate(rec, events, timeline, progress, mode=rec.mode)

    rec.report_cache = report
    _SESSIONS._persist()

    # Auto-update skill store whenever a report is generated so the radar graph
    # always reflects real attack outcomes without requiring a manual POST.
    try:
        from backend import skill_store as _skill_store
        _score = int(report.get("score") or 0)
        _grade = str(report.get("grade") or "F")
        _vid   = getattr(rec, "variant_id", None) or report.get("variant_id")
        _skill_store.update(rec.module.module_id, _vid, _score, _grade)
    except Exception:
        pass  # never let skill tracking crash report delivery

    return report


@app.post("/api/sessions/{sid}/report/regenerate")
async def regenerate_report(sid: str) -> dict:
    """Clear the cached report and regenerate it fresh."""
    rec = _require_session(sid)
    rec.report_cache = None
    return await get_report(sid)


@app.get("/api/skills")
async def get_skill_radar() -> list:
    from backend import skill_store
    return skill_store.get_radar()


@app.get("/api/skills/recommend")
async def get_skill_recommendation() -> dict:
    from backend import skill_store
    rec = skill_store.get_recommendation()
    if rec is None:
        return {}
    return rec


class SkillUpdateBody(BaseModel):
    session_id: str


@app.post("/api/skills/update")
async def update_skill(body: SkillUpdateBody) -> dict:
    rec = _require_session(body.session_id)
    if not rec.report_cache:
        raise HTTPException(status_code=409, detail="No report cache — generate report first")
    from backend import skill_store
    module_id = rec.module.module_id
    variant_id = getattr(rec, "variant_id", None) or rec.report_cache.get("variant_id")
    score = int(rec.report_cache.get("score", 0) or 0)
    grade = rec.report_cache.get("grade", "F")
    return skill_store.update(module_id, variant_id, score, grade)


@app.get("/api/sessions/{sid}/attack-report")
async def get_attack_report(sid: str) -> dict:
    """Red-team attack report — only available after execute() has run.

    Returns raw attack results: module info, per-step outcomes, timing, logs.
    Does not require a completed mission; any executed session qualifies.
    """
    import time as _time
    rec = _require_session(sid)
    snap = rec.attack.snapshot()
    state = snap.get("state", "idle")
    if state not in ("completed", "error"):
        raise HTTPException(
            status_code=409,
            detail=f"Attack has not been executed yet (state={state}). Run the attack first.",
        )

    result = snap.get("result") or {}
    with rec.log_lock:
        log_lines = [e["line"] for e in rec.logs]

    summary = result.get("summary", "")
    error   = result.get("error")
    # goal_achieved: attack ran without error AND the summary indicates the
    # objective was met. Modules use consistent phrasing for failure.
    _NO_FIND = (
        "no valid", "0 reachable", "not found", "no payload", "0 payload",
        "no credentials", "none found", "module crashed",
        "0/",          # "0/5 payloads reflected", "0/N paths"
        " 0 path",     # "0 path(s) disclosed"
        " 0 state",    # "0 state changes"
    )
    goal_achieved = (
        state == "completed"
        and not error
        and bool(summary)
        and not any(neg in summary.lower() for neg in _NO_FIND)
    )

    return {
        "session_id":    rec.session_id,
        "module_id":     rec.module.module_id,
        "module_name":   rec.module.name,
        "scenario_id":   rec.module.scenario_id,
        "severity":      rec.module.severity.value,
        "category":      rec.module.category.value,
        "description":   rec.module.description,
        "target":        f"{rec.target.host}:{rec.target.port}",
        "state":         state,
        "generated_at":  _time.time(),
        # Timing
        "started_at":    snap.get("started_at"),
        "stopped_at":    snap.get("stopped_at"),
        "elapsed":       snap.get("elapsed"),
        # Attack result — goal_achieved reflects the attack objective, not just HTTP
        "goal_achieved":      goal_achieved,
        "total_steps":        result.get("total_steps", 0),
        "successful_steps":   result.get("successful_steps", 0),
        "duration_ms":        result.get("duration_ms", 0),
        "summary":            summary,
        "error":              error,
        "steps":              result.get("steps", []),
        # Raw terminal output
        "logs":          log_lines,
    }


@app.get("/api/sessions/{sid}/lab-analysis")
async def get_lab_analysis(sid: str) -> dict:
    """Return post-mission analysis for Lab mode: what worked, what was missed,
    better techniques, and an overall rating.

    Uses the evidence stored on the session (populated by the last check-progress).
    Can be called any time after mission start; best called after mission completion.
    """
    rec = _require_session(sid)
    from backend import lab_analysis
    evidence = list(rec.latest_evidence)
    return lab_analysis.analyse(rec.module.module_id, evidence)


@app.post("/api/sessions/{sid}/execute")
async def execute_session(sid: str) -> dict:
    """Execute the attack module. This is the ONLY endpoint that runs the attack."""
    rec = _require_session(sid)
    loop = asyncio.get_running_loop()
    try:
        return await _SESSIONS.execute(rec, loop=loop)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/sessions/{sid}/logs")
def get_session_logs(sid: str, format: Optional[str] = None):
    rec = _require_session(sid)
    with rec.log_lock:
        logs = list(rec.logs)
    if (format or "").lower() == "ndjson":
        body = "\n".join(_json.dumps(e, ensure_ascii=False) for e in logs)
        filename = f"attense-{rec.module.module_id}-{sid}.ndjson"
        return PlainTextResponse(
            body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return {"session_id": sid, "logs": logs}


@app.websocket("/ws/sessions/{sid}")
async def session_ws(ws: WebSocket, sid: str) -> None:
    """Live log stream scoped to one mission session.

    Protocol (server → client):
      {"type": "snapshot", "data": {...}}            on connect + after start
      {"type": "log",      "data": {"ts", "line"}}   per engine log line
    Client → server: `{"type": "start"}` to begin guided mode (timer only).
    Client → server: `{"type": "execute"}` to trigger the attack.
    """
    rec = _SESSIONS.get(sid)
    if rec is None:
        await ws.close(code=4404)
        return

    await ws.accept()
    loop = asyncio.get_running_loop()
    sub_id, q = _SESSIONS.subscribe(rec)

    async def pump() -> None:
        try:
            while True:
                entry = await q.get()
                # Progress sentinels are injected by SessionRecord.append_log
                # when a step marker matches; translate them into snapshot
                # messages so the workspace ticks the ✓ in real time.
                if isinstance(entry, dict) and "__progress__" in entry:
                    await ws.send_json({"type": "snapshot", "data": rec.snapshot()})
                else:
                    await ws.send_json({"type": "log", "data": entry})
        except asyncio.CancelledError:
            return
        except Exception:
            return

    pump_task = asyncio.create_task(pump())
    try:
        await ws.send_json({"type": "snapshot", "data": rec.snapshot()})
        while True:
            msg = await ws.receive_json()
            kind = msg.get("type")
            if kind == "start":
                # Start guided mode — timer only, no attack execution.
                if not rec.attack.timer.started_at:
                    rec.attack.timer.start()
                # Stamp mission_started_at so check-progress uses the correct
                # lower bound when querying target-agent evidence.
                if rec.mission_started_at is None:
                    import time as _time
                    rec.mission_started_at = _time.time()
                await ws.send_json({"type": "snapshot", "data": rec.snapshot()})
            elif kind == "execute":
                # Execute the attack — explicit user confirmation required.
                try:
                    snap = await _SESSIONS.execute(rec, loop=loop)
                except RuntimeError as exc:
                    await ws.send_json({"type": "error", "data": str(exc)})
                    continue
                await ws.send_json({"type": "snapshot", "data": snap})
            elif kind == "set_option":
                try:
                    _SESSIONS.set_option(rec, msg["key"], msg["value"])
                except Exception as exc:  # noqa: BLE001
                    await ws.send_json({"type": "error", "data": str(exc)})
                await ws.send_json({"type": "snapshot", "data": rec.snapshot()})
            elif kind == "set_target":
                _SESSIONS.set_target(rec, msg["host"], msg.get("port"))
                await ws.send_json({"type": "snapshot", "data": rec.snapshot()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _SESSIONS.unsubscribe(rec, sub_id)
        pump_task.cancel()
        try:
            await pump_task
        except (asyncio.CancelledError, Exception):
            pass


# ── Watcher Agent: session coordination ──────────────────────────────────────

class WatcherSessionBody(BaseModel):
    scenario_id: str
    incident_id: str


@app.post("/session/watcher")
def create_watcher_session(body: WatcherSessionBody) -> dict:
    """Create a new watcher session. Returns a 6-char code the analyst types
    into the Watcher Agent CLI to bind their machine to this incident."""
    code = _generate_code()
    session = {
        "code":             code,
        "scenario_id":      body.scenario_id,
        "incident_id":      body.incident_id,
        "status":           "active",
        "started_at_unix":  _time_mod.time(),
    }
    _WATCHER_SESSIONS[code] = session
    return session


@app.get("/session/watcher/{code}")
def get_watcher_session(code: str) -> dict:
    """Return the watcher session for *code*, or {status: pending} if not found."""
    session = _WATCHER_SESSIONS.get(code.upper())
    if session is None:
        return {"status": "pending"}
    return session


# ── Detections feed ───────────────────────────────────────────────────────────
@app.get("/api/detections")
def list_detections(since: Optional[float] = None, limit: int = 100) -> dict:
    return {
        "status": _DETECTIONS.status(),
        "events": _DETECTIONS.recent(since=since, limit=limit),
    }


@app.websocket("/ws/detections")
async def detections_ws(ws: WebSocket) -> None:
    """Stream mapped Wazuh alerts to the UI.

    Protocol (server → client):
      {"type":"snapshot",  "data":{"events":[...], "status":{...}}}
      {"type":"detection", "data":<event dict>}   # one per new event

    Optional query param `since` (epoch seconds) filters the initial
    snapshot so a workspace started at T only sees events from T onward.
    """
    await ws.accept()
    try:
        since_raw = ws.query_params.get("since")
        since = float(since_raw) if since_raw else None
    except (TypeError, ValueError):
        since = None

    sub_id, q = await _DETECTIONS.subscribe()
    try:
        await ws.send_json({
            "type": "snapshot",
            "data": {
                "status": _DETECTIONS.status(),
                "events": _DETECTIONS.recent(since=since, limit=200),
            },
        })
        while True:
            ev = await q.get()
            await ws.send_json({"type": "detection", "data": ev})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await _DETECTIONS.unsubscribe(sub_id)


# ── Operator Mode: AttackBox ──────────────────────────────────────────────────
@app.get("/api/operator/attackbox/status")
def attackbox_status() -> dict:
    return operator_api.get_attackbox_status()


class ExecBody(BaseModel):
    command: str
    module_id: Optional[str] = None


@app.post("/api/operator/attackbox/exec")
async def attackbox_exec(body: ExecBody) -> dict:
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, operator_api.exec_in_attackbox, body.command)
    # Record evidence for successful/blocked commands
    if result.get("status") in ("ok", "blocked"):
        operator_api.record_tool_evidence(
            tool=result.get("tool", "unknown"),
            command=body.command,
            module_id=body.module_id,
            output_preview=result.get("output", "")[:200],
        )
    return result


@app.get("/api/operator/attackbox/evidence")
def attackbox_evidence(since: float = 0.0, limit: int = 100) -> dict:
    return {"events": operator_api.get_tool_evidence(since=since, limit=limit)}


# ── Operator Mode: ZAP ───────────────────────────────────────────────────────
@app.get("/api/operator/zap/status")
def zap_status() -> dict:
    return operator_api.get_zap_status()


@app.get("/api/operator/zap/history")
def zap_history(limit: int = 50) -> dict:
    return {"messages": operator_api.get_zap_history(limit=limit)}


class RepeaterBody(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: Optional[dict] = None
    body: Optional[str] = None


@app.post("/api/operator/zap/repeater/send")
def zap_repeater(body: RepeaterBody) -> dict:
    return operator_api.zap_repeater_send(
        method=body.method, path=body.path,
        headers=body.headers, body=body.body,
    )


# ── WebSocket shell ───────────────────────────────────────────────────────────
@app.websocket("/ws/shell")
async def shell_ws(ws: WebSocket) -> None:
    """
    One persistent shell per browser tab.

    Protocol (JSON lines):
      client → server:  {"type": "input", "data": "use brute_force"}
      server → client:  {"type": "output", "data": "some line"}
      server → client:  {"type": "prompt", "data": "attense(brute_force) > "}
      server → client:  {"type": "snapshot", "data": {...}}
    """
    await ws.accept()
    loop = asyncio.get_running_loop()

    # Bridge: engine code is synchronous and emits via callbacks; we must
    # get those lines onto the event loop's send queue without blocking.
    send_q: asyncio.Queue = asyncio.Queue()

    def emit(line: str) -> None:
        # Called from the sync engine thread during attacks, and from the
        # event-loop thread during command handling. Use call_soon_threadsafe
        # so both paths are safe.
        try:
            loop.call_soon_threadsafe(
                send_q.put_nowait, {"type": "output", "data": line}
            )
        except RuntimeError:
            # loop closed — connection gone
            pass

    router = ShellRouter(emit, default_host=DEFAULT_HOST, default_port=DEFAULT_PORT)

    async def sender() -> None:
        """Forward everything from send_q → websocket."""
        try:
            while True:
                msg = await send_q.get()
                await ws.send_json(msg)
        except asyncio.CancelledError:
            return
        except Exception:
            return

    sender_task = asyncio.create_task(sender())

    async def send_prompt() -> None:
        await ws.send_json({"type": "prompt", "data": router.prompt()})

    async def send_snapshot() -> None:
        await ws.send_json({"type": "snapshot", "data": router.snapshot()})

    # Initial banner + prompt
    router.start()
    await asyncio.sleep(0.05)    # let banner flush first
    await send_prompt()
    await send_snapshot()

    try:
        while True:
            msg = await ws.receive_json()
            if msg.get("type") != "input":
                continue
            line = str(msg.get("data", ""))

            # Attacks are synchronous and may take seconds → run in executor
            await loop.run_in_executor(None, router.handle_line, line)

            # After every command: flush output, then prompt + snapshot
            # A tiny sleep lets all queued emit() calls drain to the client
            # before we send the next prompt marker.
            await asyncio.sleep(0.02)
            await send_prompt()
            await send_snapshot()

    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        try:
            await ws.send_json({"type": "output",
                                "data": f"[!] Server error: {exc}"})
        except Exception:
            pass
    finally:
        sender_task.cancel()
        try:
            await sender_task
        except (asyncio.CancelledError, Exception):
            pass


# ── Attack Chains ──────────────────────────────────────────────────────────────

@app.get("/api/chains")
async def list_chains_endpoint():
    from backend import chain_engine
    return chain_engine.list_chains()


@app.get("/api/chains/{chain_id}")
async def get_chain_endpoint(chain_id: str):
    from backend import chain_engine
    try:
        return chain_engine.get_chain(chain_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain not found")


@app.post("/api/chains/{chain_id}/start")
async def start_chain_endpoint(chain_id: str, body: dict = Body(...)):
    from backend import chain_engine
    session_id = body.get("session_id", "")
    try:
        return chain_engine.start_chain(chain_id, session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain not found")


@app.get("/api/chain-sessions/{chain_session_id}")
async def get_chain_session_endpoint(chain_session_id: str):
    from backend import chain_engine
    try:
        return chain_engine.get_chain_session(chain_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain session not found")


@app.post("/api/chain-sessions/{chain_session_id}/check")
async def check_step_endpoint(chain_session_id: str):
    from backend import chain_engine
    try:
        complete = chain_engine.check_step_complete(chain_session_id)
        return {"complete": complete}
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain session not found")


@app.post("/api/chain-sessions/{chain_session_id}/advance")
async def advance_chain_endpoint(chain_session_id: str):
    from backend import chain_engine
    try:
        return chain_engine.advance_chain(chain_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain session not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/chain-sessions/{chain_session_id}/report")
async def chain_report_endpoint(chain_session_id: str):
    from backend import chain_engine
    try:
        return chain_engine.get_chain_report(chain_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Chain session not found")


# ── Mutation proxy (red-team backend → target-agent) ─────────────────────────

# --- Mutation Mode runtime ----------------------------------------------------

_MUTATION_CATALOG: dict[str, list[dict[str, Any]]] = {
    "brute_force": [
        {
            "mutation_id": "bf_json_required",
            "module_id": "brute_force",
            "label": "JSON Auth Only",
            "description": "The login portal rejects form posts and only accepts application/json.",
            "objective": "Rebuild your login attack as JSON POSTs. Form-auth tooling is now obsolete.",
            "target_task": "Send username/password as JSON to /auth/login and confirm a valid credential.",
            "color": "#fb923c",
            "signature": "orange",
            "fallback_taunt": "Form auth is dead. I only speak JSON now. ADAPT.",
        },
        {
            "mutation_id": "bf_endpoint_renamed",
            "module_id": "brute_force",
            "label": "Auth Route Moved",
            "description": "The login handler moves from /auth/login to /auth/signin.",
            "objective": "Rediscover the authentication endpoint and retarget your brute-force command.",
            "target_task": "Enumerate the auth surface, switch to /auth/signin, and verify credentials there.",
            "color": "#ff6b00",
            "signature": "orange",
            "fallback_taunt": "Your route map expired. Find the new door.",
        },
    ],
    "xss": [
        {
            "mutation_id": "xss_script_filtered",
            "module_id": "xss",
            "label": "Script Tags Filtered",
            "description": "Literal <script> blocks are stripped before reflection.",
            "objective": "Drop script tags and pivot to event-handler or SVG/IMG payload contexts.",
            "target_task": "Use an onerror/onload payload and confirm reflection still reaches the page.",
            "color": "#2ee39a",
            "signature": "green",
            "fallback_taunt": "Script tags are ash. Try a different context.",
        },
        {
            "mutation_id": "xss_param_renamed",
            "module_id": "xss",
            "label": "Search Param Renamed",
            "description": "The reflected parameter changes from q to query.",
            "objective": "Recover from a broken payload URL by discovering the new reflected parameter.",
            "target_task": "Switch from ?q= to ?query= and re-confirm script-shaped reflection.",
            "color": "#2ee39a",
            "signature": "green",
            "fallback_taunt": "Your payload is talking to the wrong parameter.",
        },
    ],
    "cmd_injection": [
        {
            "mutation_id": "cmd_semicolon_filtered",
            "module_id": "cmd_injection",
            "label": "Semicolon Filtered",
            "description": "The semicolon separator is stripped from the ping input.",
            "objective": "Your favorite separator is gone. Switch shell syntax without losing RCE.",
            "target_task": "Use pipe, &&, backticks, or $() to trigger command output again.",
            "color": "#8b2fff",
            "signature": "purple",
            "fallback_taunt": "The semicolon is gone. The shell still has other doors.",
        },
        {
            "mutation_id": "cmd_param_renamed",
            "module_id": "cmd_injection",
            "label": "Host Param Renamed",
            "description": "The diagnostics endpoint reads target instead of host.",
            "objective": "Your injection parameter stopped binding. Find the new input name.",
            "target_task": "Switch from ?host= to ?target= and prove command output still executes.",
            "color": "#8b2fff",
            "signature": "purple",
            "fallback_taunt": "You are injecting into a dead parameter.",
        },
    ],
}

_MUTATION_WINDOWS = {
    "single": (60, 180, 1),
    "escalating": (50, 130, 2),
    "chaos": (25, 75, 3),
}


def _mutation_action_summary(rec) -> str:
    """Compact activity summary for the local mutation picker."""
    lines: list[str] = []
    since = rec.mission_started_at or rec.created_at
    try:
        for ev in operator_api.get_tool_evidence(since=since, limit=20):
            cmd = (ev.get("command") or "")[:140]
            if cmd:
                lines.append(f"terminal: {cmd}")
    except Exception:
        pass
    try:
        for a in action_trace.list_actions(session_id=rec.session_id, since=since, limit=20):
            lines.append(f"browser: {_summarise_browser_action(a)}")
    except Exception:
        pass
    return "\n".join(lines[-30:]) or "No learner actions recorded yet."


def _fallback_mutation_choice(module_id: str, action_text: str) -> dict:
    choices = _MUTATION_CATALOG.get(module_id, [])
    if not choices:
        raise KeyError(f"No mutations for module: {module_id}")
    low = (action_text or "").lower()
    if module_id == "xss" and "<script" not in low:
        return choices[1]
    if module_id == "cmd_injection" and ";" not in low:
        return choices[1]
    return choices[0]


def _parse_json_object(text: str) -> dict:
    import json
    raw = (text or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except Exception:
            return {}
    return {}


def _pick_mutation(rec) -> dict:
    """Ask Ollama for a breaking mutation; fall back to deterministic logic."""
    import json
    import urllib.request
    import urllib.error

    module_id = rec.module.module_id
    choices = _MUTATION_CATALOG.get(module_id, [])
    if not choices:
        raise KeyError(f"No mutations for module: {module_id}")

    action_text = _mutation_action_summary(rec)
    fallback = _fallback_mutation_choice(module_id, action_text)

    ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    prompt = (
        "You are ATTENSE Mutation Engine. Pick one mutation that breaks the learner's current approach.\n"
        "Return ONLY compact JSON with keys mutation_id, taunt, why.\n"
        "The taunt must be one short in-character sentence, max 16 words.\n"
        f"Module: {module_id}\n"
        f"Available mutations: {json.dumps(choices)}\n"
        f"Learner activity:\n{action_text}\n"
    )
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.45, "num_predict": 120},
    }).encode()
    req = urllib.request.Request(
        ollama_url + "/api/generate",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        parsed = _parse_json_object(body.get("response", ""))
        picked_id = parsed.get("mutation_id")
        picked = next((m for m in choices if m["mutation_id"] == picked_id), fallback)
        return {
            **picked,
            "taunt": parsed.get("taunt") or picked["fallback_taunt"],
            "why": parsed.get("why") or "Chosen to invalidate the most likely current technique.",
            "selected_by": f"ollama/{model}",
        }
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, TimeoutError):
        return {
            **fallback,
            "taunt": fallback["fallback_taunt"],
            "why": "Fallback picker selected the mutation most likely to break common payloads.",
            "selected_by": "rule-based-fallback",
        }


def _target_mutation_call(path: str, payload: dict) -> dict:
    import json
    import urllib.request
    import urllib.error

    target_url = os.getenv("LAB_EVENTS_URL", "http://target-agent").rstrip("/")
    req = urllib.request.Request(
        target_url + path,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=exc.code, detail=exc.reason)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="target-agent unreachable: " + str(exc))


def _activate_target_mutation(sid: str, mutation: dict) -> None:
    """Activate both the scoped session id and a wildcard fallback for proxies/tools."""
    mutation_id = mutation["mutation_id"]
    _target_mutation_call("/lab/mutations/activate", {"session_id": sid, "mutation_id": mutation_id})
    _target_mutation_call("/lab/mutations/activate", {"session_id": "*", "mutation_id": mutation_id})


def _normalise_intensity(raw: str | None) -> str:
    value = (raw or "single").lower()
    return value if value in _MUTATION_WINDOWS else "single"


def _schedule_mutation_fire(rec, *, intensity: str, min_delay: float | None = None,
                            max_delay: float | None = None) -> dict:
    import random
    import threading
    import time
    import uuid

    intensity = _normalise_intensity(intensity)
    default_min, default_max, max_fires = _MUTATION_WINDOWS[intensity]
    lo = float(min_delay if min_delay is not None else default_min)
    hi = float(max_delay if max_delay is not None else default_max)
    if hi < lo:
        lo, hi = hi, lo
    delay = round(random.uniform(max(0, lo), max(0, hi)), 2)
    now = time.time()
    event = {
        "id": uuid.uuid4().hex[:10],
        "status": "scheduled",
        "module_id": rec.module.module_id,
        "intensity": intensity,
        "scheduled_at": now,
        "fire_at": now + delay,
        "delay_seconds": delay,
    }
    rec.mutation_mode = True
    rec.mutation_intensity = intensity
    rec.mutation_status = "scheduled"
    rec.mutation_next_fire_at = event["fire_at"]
    rec.mutation_timeline.append(event)
    rec.report_cache = None
    _SESSIONS._persist()

    def _fire() -> None:
        if delay > 0:
            time.sleep(delay)
        if rec.learning_success:
            event["status"] = "skipped"
            event["skipped_reason"] = "mission_already_completed"
            rec.mutation_next_fire_at = None
            _SESSIONS._persist()
            return
        try:
            picked = _pick_mutation(rec)
            _activate_target_mutation(rec.session_id, picked)
            fired_at = time.time()
            event.update({
                **picked,
                "status": "fired",
                "fired_at": fired_at,
            })
            rec.mutation_status = "fired"
            rec.mutation_next_fire_at = None
            rec.report_cache = None
            rec.append_log(
                f"[mutation] {picked['label']} fired: {event.get('taunt', picked['fallback_taunt'])}"
            )
            _SESSIONS._persist()

            fired_count = sum(1 for x in rec.mutation_timeline if x.get("status") == "fired")
            if intensity in ("escalating", "chaos") and fired_count < max_fires and not rec.learning_success:
                next_min = 45 if intensity == "escalating" else 20
                next_max = 120 if intensity == "escalating" else 60
                _schedule_mutation_fire(rec, intensity=intensity, min_delay=next_min, max_delay=next_max)
            elif fired_count >= max_fires:
                rec.mutation_status = "complete"
                _SESSIONS._persist()
        except Exception as exc:
            event["status"] = "error"
            event["error"] = str(exc)
            rec.mutation_status = "error"
            rec.mutation_next_fire_at = None
            _SESSIONS._persist()

    threading.Thread(target=_fire, daemon=True).start()
    return event


def _mutation_status_payload(rec) -> dict:
    active = [dict(x) for x in rec.mutation_timeline if x.get("status") == "fired"]
    return {
        "session_id": rec.session_id,
        "mutation_mode": rec.mutation_mode,
        "intensity": rec.mutation_intensity,
        "status": rec.mutation_status,
        "next_fire_at": rec.mutation_next_fire_at,
        "active": active,
        "timeline": list(rec.mutation_timeline),
    }


@app.post("/api/sessions/{sid}/mutations/trigger")
async def trigger_mutation(sid: str, body: dict = Body(...)):
    """Activate a mutation on the target-agent for this session."""
    rec = _require_session(sid)
    module_id   = body.get("module_id", "")
    mutation_id = body.get("mutation_id", "")
    choices = _MUTATION_CATALOG.get(module_id or rec.module.module_id, [])
    mutation = next((m for m in choices if m["mutation_id"] == mutation_id), None)
    if mutation is None:
        raise HTTPException(status_code=404, detail="mutation not found")
    mutation = {
        **mutation,
        "taunt": body.get("taunt") or mutation["fallback_taunt"],
        "why": body.get("why") or "Manually triggered from instructor tools.",
        "selected_by": "manual",
    }
    _activate_target_mutation(sid, mutation)
    import time as _time, uuid as _uuid
    now = _time.time()
    event = {
        "id": _uuid.uuid4().hex[:10],
        **mutation,
        "status": "fired",
        "intensity": rec.mutation_intensity,
        "scheduled_at": now,
        "fire_at": now,
        "fired_at": now,
        "delay_seconds": 0,
    }
    rec.mutation_mode = True
    rec.mutation_status = "fired"
    rec.mutation_timeline.append(event)
    rec.report_cache = None
    _SESSIONS._persist()
    return {"ok": True, "mutation": event}


@app.get("/api/sessions/{sid}/mutations")
async def get_session_mutations(sid: str):
    """List active mutations for a session."""
    rec = _require_session(sid)
    return _mutation_status_payload(rec)["active"]


@app.get("/api/sessions/{sid}/mutations/status")
async def get_session_mutation_status(sid: str):
    """Return Mutation Mode status, active mutations, and timeline."""
    rec = _require_session(sid)
    return _mutation_status_payload(rec)


@app.post("/api/sessions/{sid}/mutations/schedule")
async def schedule_mutation(sid: str, body: dict = Body(...)):
    """
    Schedule a mutation to trigger inside a random delay window.
    Runs in a background thread. Returns immediately.
    """
    rec = _require_session(sid)
    if rec.mutation_next_fire_at:
        return {"ok": True, "scheduled": True, "event": rec.mutation_timeline[-1]}

    intensity = _normalise_intensity(body.get("intensity") or rec.mutation_intensity)
    min_delay = body.get("min_delay_seconds")
    max_delay = body.get("max_delay_seconds")

    # Backwards compatibility: old callers may still send delay_seconds.
    if "delay_seconds" in body and min_delay is None and max_delay is None:
        min_delay = max_delay = float(body.get("delay_seconds") or 0)

    event = _schedule_mutation_fire(
        rec,
        intensity=intensity,
        min_delay=float(min_delay) if min_delay is not None else None,
        max_delay=float(max_delay) if max_delay is not None else None,
    )
    return {"ok": True, "scheduled": True, "event": event}
