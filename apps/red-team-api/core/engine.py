"""
core/engine.py — Attack execution engine (CLI build, no Qt).

Runs modules synchronously on the operator thread. In a CLI environment
there is no GUI to keep responsive, so we drop QThread entirely. This
removes the PySide6 dependency from the entire core.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from core import event_sink
from core.base_module import BaseModule
from core.logger import LogManager
from core.models import AttackResult, TargetConfig

# ── malicious_action_executed emission ──────────────────────────────────────
# Tells attense-app's incident pipeline a red-team module actually fired
# against the target. This anchors Incident.start_time so TTD (time-to-detect)
# is measurable, instead of falling back to using the first alert_raised for
# both start and detection (see ATTENSE_app/incidents/incident.py).
# Actual POST lives in core/event_sink.py, shared with backend/zap_bridge.py.


def _outcome_for(result: AttackResult) -> str:
    """Map an AttackResult onto the Event schema's outcome enum."""
    if result.error:
        return "failure"
    if result.total_steps and result.successful_steps == result.total_steps:
        return "success"
    if result.successful_steps:
        return "partial"
    return "failure"


class Engine:
    """
    Orchestration layer between the operator and attack modules.

    Responsibilities:
      - Hold discovered modules
      - Validate options
      - Execute a module and wire its log stream through LogManager
      - Persist the AttackResult via LogManager.log_result
    """

    def __init__(
        self,
        modules: dict[str, BaseModule],
        log_mgr: LogManager,
    ) -> None:
        self.modules = modules
        self.log = log_mgr

    # ── Public API ────────────────────────────────────────────────────────────
    def run_module(
        self,
        module_id: str,
        target: TargetConfig,
        opts: dict | None = None,
        actor_id: str | None = None,
        incident_id: str | None = None,
    ) -> AttackResult:
        """
        Validate and execute an attack module synchronously.

        Returns the AttackResult. Errors are captured into AttackResult.error
        rather than raised, so the operator never loses the container REPL.

        actor_id identifies the operator for the malicious_action_executed
        event emitted below (see _emit_malicious_action_event). incident_id,
        if given, tags the event with a specific room's incident instead of
        the env var INCIDENT_ID fallback (see engine/session.py::AttackSession).
        """
        opts = opts or {}
        module = self.modules.get(module_id)
        if module is None:
            err_result = AttackResult(
                module_id=module_id,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=f"Unknown module: {module_id}",
                summary=f"Unknown module: {module_id}",
            )
            self.log.error(err_result.summary)
            return err_result

        err = module.validate(opts, target)
        if err:
            err_result = AttackResult(
                module_id=module.module_id,
                module_name=module.name,
                scenario_id=module.scenario_id,
                target=target.base_url,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=err,
                summary=err,
            )
            self.log.error(err)
            return err_result

        self.log.info(f"[>] Starting [{module.name}] against {target.base_url}")

        t0 = time.monotonic()
        try:
            result = module.execute(
                target=target,
                opts=opts,
                log_fn=self.log.info,
            )
            result.duration_ms = round((time.monotonic() - t0) * 1000, 1)
        except Exception as exc:  # noqa: BLE001 (we want all exceptions contained)
            result = AttackResult(
                module_id=module.module_id,
                module_name=module.name,
                scenario_id=module.scenario_id,
                target=target.base_url,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.monotonic() - t0) * 1000, 1),
                error=str(exc),
                summary=f"Module crashed: {exc}",
            )
            self.log.error(result.summary)

        self.log.log_result(result)
        self._emit_malicious_action_event(module, target, opts, result, actor_id, incident_id)
        return result

    # ── Event emission ───────────────────────────────────────────────────────
    def _emit_malicious_action_event(
        self,
        module: BaseModule,
        target: TargetConfig,
        opts: dict,
        result: AttackResult,
        actor_id: str | None,
        incident_id: str | None = None,
    ) -> None:
        """
        POST a malicious_action_executed event to attense-app's incident
        pipeline (see module docstring above for why).

        incident_id, if not given (e.g. the operator hasn't joined a room),
        falls back to the env var INCIDENT_ID -- today's behavior, unchanged.
        """
        incident_id = incident_id or os.environ.get("INCIDENT_ID")
        if not incident_id:
            self.log.warning(
                "INCIDENT_ID not set -- skipping malicious_action_executed "
                f"event for [{module.name}] (nothing to tag it with)."
            )
            return

        event_sink.post_malicious_action_event(
            event_id=result.run_id,
            incident_id=incident_id,
            scenario_id=module.scenario_id,
            actor_id=actor_id or "redteam-operator",
            target_id=target.base_url,
            outcome=_outcome_for(result),
            # TTD anchor = attack START/trigger time, not completion (report
            # Phase 4: the old finished_at collapsed or inflated TTD). Fall back
            # to finished_at only if a module left started_at empty.
            timestamp=result.started_at or result.finished_at,
            metadata={
                "module_id": module.module_id,
                "opts": opts,
                "result": result.to_dict(),
            },
            log_fn=self.log.warning,
        )
