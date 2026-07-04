"""
core/engine.py — Attack execution engine (CLI build, no Qt).

Runs modules synchronously on the operator thread. In a CLI environment
there is no GUI to keep responsive, so we drop QThread entirely. This
removes the PySide6 dependency from the entire core.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from core.base_module import BaseModule
from core.logger import LogManager
from core.models import AttackResult, TargetConfig


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
    ) -> AttackResult:
        """
        Validate and execute an attack module synchronously.

        Returns the AttackResult. Errors are captured into AttackResult.error
        rather than raised, so the operator never loses the container REPL.
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
        return result
