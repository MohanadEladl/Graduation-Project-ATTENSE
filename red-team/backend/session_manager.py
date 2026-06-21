"""
backend/session_manager.py — REST-facing session store on top of AttackSession.

Each mission the UI opens becomes a SessionRecord: the existing AttackSession
drives the engine; we wrap it to keep the run logic (synchronous, blocking
`engine.run_module`) exactly the same while exposing a clean REST + WS surface
for the tutorial/lab workspace.

Nothing here duplicates attack logic — every path ends up calling the same
engine.run_module the legacy shell calls through `use` + `start`.

Mode values:
  tutorial — guided walkthrough with rich explanations (no tool requirement)
  lab      — realistic pentesting via AttackBox terminal/ZAP (tool evidence required)
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.base_module import BaseModule
from core.models import TargetConfig
from engine.session import AttackSession

# Temp file — lives inside the container; removed when `docker rm` clears /tmp
_PERSIST_PATH = os.getenv("SESSION_STORE", "/tmp/attense_sessions.json")


# Small ring buffer of recent log lines per session.
_MAX_LOG_LINES = 2000


@dataclass
class SessionRecord:
    session_id: str
    module: BaseModule
    target: TargetConfig
    attack: AttackSession
    # Shared append-only log. We protect it so the engine thread and the
    # event loop can both touch it without races.
    logs: List[dict] = field(default_factory=list)
    log_lock: threading.Lock = field(default_factory=threading.Lock)
    # Subscribers receive every new log line as a dict {ts, line}.
    # Keys are arbitrary unique ids; values are queues to push into.
    subscribers: Dict[str, "asyncio.Queue[dict]"] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    # Completed steps tracked by index. The engine doesn't currently emit
    # per-step events; the shell just runs the whole module. For now we mark
    # all steps complete when the attack completes successfully.
    completed_steps: List[int] = field(default_factory=list)
    # When the learner clicked START on the mission. Used as the lower bound
    # when querying target-agent's evidence stream for progress.
    mission_started_at: Optional[float] = None

    # ── Mode: "tutorial" (guided walkthrough) | "lab" (real tool usage) ──────
    mode: str = "tutorial"
    # ── Active attack variant within the module (e.g. "hydra_targeted") ─────
    variant_id: Optional[str] = None

    # ── Learning state (persisted across Check Progress calls) ───────────────
    learning_state: str = "idle"  # idle | in_progress | completed
    learning_completed_tasks: List[int] = field(default_factory=list)
    learning_total_tasks: int = 0
    learning_progress_percent: int = 0
    learning_success: bool = False
    learning_completed_at: Optional[float] = None
    latest_evidence: List[dict] = field(default_factory=list)

    # Cached generated report (set by the /report endpoint)
    report_cache: Optional[dict] = None

    # Resolved operator identity (attense-app username), if the create-session
    # caller forwarded a valid session token. See backend/identity.py.
    actor_id: Optional[str] = None

    # Mutation Mode: a normal mission with adaptive target shifts layered on.
    mutation_mode: bool = False
    mutation_intensity: str = "single"
    mutation_status: str = "idle"  # idle | scheduled | fired | complete
    mutation_next_fire_at: Optional[float] = None
    mutation_timeline: List[dict] = field(default_factory=list)

    def normalize_learning_state(self) -> None:
        """Repair persisted state combinations that cannot be produced now."""
        if self.learning_success:
            self.learning_state = "completed"
            return
        if self.learning_state == "completed":
            self.learning_state = "in_progress" if self.mission_started_at else "idle"
            self.learning_completed_at = None

    def update_learning_progress(self, progress: dict) -> None:
        """Persist lab_progress.compute() results into session state."""
        self.learning_completed_tasks = list(progress.get("completed_tasks", []))
        self.learning_total_tasks = len(progress.get("tasks", []))
        self.learning_progress_percent = int(progress.get("progress_percent", 0))
        self.learning_success = bool(progress.get("success", False))
        self.latest_evidence = list(progress.get("evidence", []))[:20]
        if self.learning_success and not self.learning_completed_at:
            self.learning_completed_at = time.time()
            self.learning_state = "completed"
        elif self.learning_progress_percent > 0:
            if self.learning_state == "idle":
                self.learning_state = "in_progress"

    def append_log(self, line: str, *, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        entry = {"ts": time.time(), "line": line}
        with self.log_lock:
            self.logs.append(entry)
            if len(self.logs) > _MAX_LOG_LINES:
                del self.logs[: len(self.logs) - _MAX_LOG_LINES]
            subs = list(self.subscribers.values())
            progressed = self._match_step_markers(line)
        # Fan out to any live WS listeners. If called from a worker thread,
        # we need the main loop to schedule the put.
        for q in subs:
            try:
                if loop is not None:
                    loop.call_soon_threadsafe(q.put_nowait, entry)
                else:
                    q.put_nowait(entry)
            except Exception:
                # Dead subscriber; it'll be cleaned up when the WS disconnects.
                pass
        if progressed:
            # Announce progress out-of-band so the workspace can tick the ✓.
            prog = {"ts": entry["ts"], "__progress__": list(self.completed_steps)}
            for q in subs:
                try:
                    if loop is not None:
                        loop.call_soon_threadsafe(q.put_nowait, prog)
                    else:
                        q.put_nowait(prog)
                except Exception:
                    pass

    def _match_step_markers(self, line: str) -> bool:
        """Honest per-step auto-complete: a step is done the first time any of
        its `markers` appears in a log line. Steps without `markers` fall back
        to the whole-module completion that `SessionManager.start` does.

        Returns True when a new step was marked complete.
        """
        steps = getattr(self.module, "steps", None) or []
        if not steps or not line:
            return False
        low = line.lower()
        changed = False
        for idx, step in enumerate(steps):
            if idx in self.completed_steps:
                continue
            markers = step.get("markers") if isinstance(step, dict) else None
            if not markers:
                continue
            if any(str(m).lower() in low for m in markers):
                self.completed_steps.append(idx)
                changed = True
        return changed

    def snapshot(self) -> dict:
        self.normalize_learning_state()
        snap = self.attack.snapshot()
        total = len(getattr(self.module, "steps", []) or [])
        return {
            "session_id":      self.session_id,
            "module_id":       self.module.module_id,
            "module_name":     self.module.name,
            "scenario_id":     self.module.scenario_id,
            "severity":        self.module.severity.value,
            "state":           snap.get("state", "idle"),
            "started_at":      snap.get("started_at"),
            "stopped_at":      snap.get("stopped_at"),
            "elapsed":         snap.get("elapsed"),
            "result":          snap.get("result"),
            "options":         dict(self.attack.options),
            "target":          {"host": self.target.host, "port": self.target.port},
            "total_steps":     total,
            "completed_steps": list(self.completed_steps),
            "mission_started_at": self.mission_started_at,
            "created_at":      self.created_at,
            # Mode + learning state
            "mode":                      self.mode,
            "variant_id":                self.variant_id,
            "learning_state":            self.learning_state,
            "learning_completed_tasks":  list(self.learning_completed_tasks),
            "learning_total_tasks":      self.learning_total_tasks,
            "learning_progress_percent": self.learning_progress_percent,
            "learning_success":          self.learning_success,
            "learning_completed_at":     self.learning_completed_at,
            "learning_duration_s": (
                round(self.learning_completed_at - self.mission_started_at)
                if self.learning_completed_at and self.mission_started_at else None
            ),
            "mutation_mode":         self.mutation_mode,
            "mutation_intensity":    self.mutation_intensity,
            "mutation_status":       self.mutation_status,
            "mutation_next_fire_at": self.mutation_next_fire_at,
            "mutation_timeline":     list(self.mutation_timeline),
            "actor_id":              self.actor_id,
        }


class SessionManager:
    """Owns every open mission session for the lifetime of the process."""

    def __init__(self, modules: Dict[str, BaseModule], default_host: str, default_port: int) -> None:
        self._modules = modules
        self._default_host = default_host
        self._default_port = default_port
        self._sessions: Dict[str, SessionRecord] = {}
        self._lock = threading.Lock()
        self._load_persisted()

    # ── JSON persistence (survives restarts; gone when container is removed) ──

    def _persist(self) -> None:
        """Write all session snapshots + report caches to the temp JSON file."""
        try:
            rows = []
            with self._lock:
                records = list(self._sessions.values())
            for rec in records:
                snap = rec.snapshot()
                snap["report_cache"] = rec.report_cache
                rows.append(snap)
            tmp = _PERSIST_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"sessions": rows}, f)
            os.replace(tmp, _PERSIST_PATH)
        except Exception:
            pass  # persistence is best-effort; never crash the server

    def _load_persisted(self) -> None:
        """Restore sessions from the temp JSON file on startup."""
        if not os.path.exists(_PERSIST_PATH):
            return
        try:
            with open(_PERSIST_PATH) as f:
                data = json.load(f)
        except Exception:
            return

        for snap in data.get("sessions", []):
            module_id = snap.get("module_id")
            mod = self._modules.get(module_id)
            if mod is None:
                continue
            sid = snap.get("session_id")
            if not sid or sid in self._sessions:
                continue

            target = TargetConfig(
                host=snap.get("target", {}).get("host", self._default_host),
                port=int(snap.get("target", {}).get("port", self._default_port)),
            )
            actor_id = snap.get("actor_id")
            # No-op emit — restored sessions don't stream logs
            attack = AttackSession(mod, target, lambda _: None, actor_id=actor_id)
            # Restore engine state so snapshot() returns the right values
            saved_state = snap.get("state", "completed")
            attack.state = saved_state if saved_state in ("idle", "running", "completed", "error") else "completed"

            rec = SessionRecord(
                session_id=sid,
                module=mod,
                mode=snap.get("mode", "tutorial"),
                target=target,
                attack=attack,
                actor_id=actor_id,
            )
            rec.created_at             = snap.get("created_at", time.time())
            rec.mission_started_at     = snap.get("mission_started_at")
            rec.completed_steps        = snap.get("completed_steps", [])
            rec.variant_id             = snap.get("variant_id")
            rec.learning_state         = snap.get("learning_state", "idle")
            rec.learning_completed_tasks  = snap.get("learning_completed_tasks", [])
            rec.learning_total_tasks      = snap.get("learning_total_tasks", 0)
            rec.learning_progress_percent = snap.get("learning_progress_percent", 0)
            rec.learning_success          = snap.get("learning_success", False)
            rec.learning_completed_at     = snap.get("learning_completed_at")
            rec.report_cache              = snap.get("report_cache")
            rec.latest_evidence           = snap.get("latest_evidence", [])
            rec.mutation_mode             = bool(snap.get("mutation_mode", False))
            rec.mutation_intensity        = snap.get("mutation_intensity", "single")
            rec.mutation_status           = snap.get("mutation_status", "idle")
            rec.mutation_next_fire_at     = snap.get("mutation_next_fire_at")
            rec.mutation_timeline         = snap.get("mutation_timeline", [])
            rec.normalize_learning_state()

            self._sessions[sid] = rec

    # ── Module registry passthrough ──────────────────────────────────────────
    def get_module(self, module_id: str) -> Optional[BaseModule]:
        return self._modules.get(module_id)

    # ── Session lifecycle ────────────────────────────────────────────────────
    def create(
        self,
        module_id: str,
        *,
        mode: str = "tutorial",
        mutation_mode: bool = False,
        mutation_intensity: str = "single",
        actor_id: Optional[str] = None,
        loop: asyncio.AbstractEventLoop,
    ) -> SessionRecord:
        mod = self._modules.get(module_id)
        if mod is None:
            raise KeyError(f"Unknown module: {module_id}")

        # Normalise legacy mode names for backwards compatibility
        if mode == "guided":
            mode = "tutorial"
        elif mode == "operator":
            mode = "lab"
        if mode not in ("tutorial", "lab"):
            mode = "tutorial"

        session_id = uuid.uuid4().hex[:12]
        target = TargetConfig(host=self._default_host, port=self._default_port)

        # Forward-declare the record so the emit callback can capture it.
        record: SessionRecord  # populated below
        def emit(line: str) -> None:
            record.append_log(line, loop=loop)

        attack = AttackSession(mod, target, emit, actor_id=actor_id)
        record = SessionRecord(
            session_id=session_id,
            module=mod,
            mode=mode,
            target=target,
            attack=attack,
            actor_id=actor_id,
            mutation_mode=bool(mutation_mode),
            mutation_intensity=mutation_intensity if mutation_intensity in ("single", "escalating", "chaos") else "single",
        )
        # Seed the log with the session banner.
        attack.banner()

        with self._lock:
            self._sessions[session_id] = record
        self._persist()
        return record

    def get(self, session_id: str) -> Optional[SessionRecord]:
        with self._lock:
            return self._sessions.get(session_id)

    def list(self) -> List[dict]:
        with self._lock:
            return [r.snapshot() for r in self._sessions.values()]

    def delete(self, session_id: str) -> bool:
        with self._lock:
            removed = self._sessions.pop(session_id, None) is not None
        if removed:
            self._persist()
        return removed

    # ── Actions ──────────────────────────────────────────────────────────────
    def set_option(self, record: SessionRecord, key: str, value: str) -> None:
        """Reuse the shell's `set <opt> <value>` path so validation matches."""
        record.attack._cmd_set([key, value])  # noqa: SLF001

    def set_target(self, record: SessionRecord, host: str, port: Optional[int]) -> None:
        record.target.host = host
        if port is not None:
            record.target.port = int(port)
        record.attack._info(f"TARGET → {record.target.base_url}")  # noqa: SLF001

    async def execute(self, record: SessionRecord, *, loop: asyncio.AbstractEventLoop) -> dict:
        """Run the attack on the executor; return the final snapshot."""
        if record.attack.state == "running":
            raise RuntimeError("attack already running")

        def _run() -> None:
            record.attack._cmd_execute([])  # noqa: SLF001
            # When start finishes without error, mark all declared steps complete.
            if record.attack.state == "completed":
                steps = getattr(record.module, "steps", []) or []
                record.completed_steps = list(range(len(steps)))

        await loop.run_in_executor(None, _run)
        return record.snapshot()

    # ── Logs / streaming ─────────────────────────────────────────────────────
    def subscribe(self, record: SessionRecord) -> tuple[str, "asyncio.Queue[dict]"]:
        sub_id = uuid.uuid4().hex[:8]
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        with record.log_lock:
            record.subscribers[sub_id] = q
            backfill = list(record.logs)
        # Replay existing logs so late subscribers see the banner.
        for entry in backfill:
            try: q.put_nowait(entry)
            except asyncio.QueueFull: break
        return sub_id, q

    def unsubscribe(self, record: SessionRecord, sub_id: str) -> None:
        with record.log_lock:
            record.subscribers.pop(sub_id, None)

    # ── Backwards-compatibility shims ────────────────────────────────────────
    # Keep old attribute names working so any leftover call sites don't break
    # until they are updated.
    @staticmethod
    def _compat_progress_update(record: "SessionRecord", progress: dict) -> None:
        record.update_learning_progress(progress)
