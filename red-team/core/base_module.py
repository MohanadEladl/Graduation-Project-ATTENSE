"""
core/base_module.py — Abstract base class for all attack modules.

Every module in modules/ must subclass BaseModule and implement execute().
The engine calls execute() and receives an AttackResult.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import requests

from core.models import (
    AttackResult,
    Category,
    ModuleOption,
    Severity,
    StepResult,
    TargetConfig,
)


class BaseModule(ABC):
    """Contract that every attack module must satisfy."""

    # ── Module metadata (override in subclass) ────────────────────────────────
    module_id: str = ""
    name: str = ""
    description: str = ""
    category: Category = Category.RECON
    scenario_id: str = ""          # maps to ATTENSE APP-XX
    severity: Severity = Severity.INFO

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "ATTENSE-RedTeam/2.0 (lab-internal)",
        })

    # ── Options each module can declare ────────────────────────────────────────
    @abstractmethod
    def options(self) -> list[ModuleOption]:
        """Return the configurable options for this module."""
        ...

    # ── Validation ─────────────────────────────────────────────────────────────
    def validate(self, opts: dict, target: TargetConfig) -> str | None:
        """Return an error string if options are invalid, else None."""
        for opt in self.options():
            if opt.required and not opts.get(opt.name):
                return f"Missing required option: {opt.display_name}"
        return None

    # ── Execution ──────────────────────────────────────────────────────────────
    @abstractmethod
    def execute(
        self,
        target: TargetConfig,
        opts: dict,
        log_fn=None,
    ) -> AttackResult:
        """
        Run the attack module.

        Args:
            target:  Global target configuration.
            opts:    Dict of option values keyed by ModuleOption.name.
            log_fn:  Callable(str) to emit live log lines to the GUI.

        Returns:
            AttackResult with all steps and summary.
        """
        ...

    # ── Helpers available to all modules ───────────────────────────────────────

    def _log(self, log_fn, msg: str) -> None:
        if log_fn:
            log_fn(msg)

    def _get(self, url: str, **kwargs) -> StepResult:
        return self._request("GET", url, **kwargs)

    def _post(self, url: str, **kwargs) -> StepResult:
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, label: str = "",
                 timeout: int = 10, **kwargs) -> StepResult:
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        t0 = time.monotonic()
        try:
            resp = self._session.request(method, url, timeout=timeout, **kwargs)
            lat = round((time.monotonic() - t0) * 1000, 1)
            return StepResult(
                label=label or f"{method} {url}",
                url=resp.url,
                status_code=resp.status_code,
                latency_ms=lat,
                success=True,
                detail=resp.text[:4000],
            )
        except requests.RequestException as exc:
            lat = round((time.monotonic() - t0) * 1000, 1)
            return StepResult(
                label=label or f"{method} {url}",
                url=url,
                latency_ms=lat,
                success=False,
                detail=str(exc),
            )

    def _make_result(self, target: TargetConfig, steps: list[StepResult],
                     summary: str = "", started: str = "") -> AttackResult:
        now = datetime.now(timezone.utc).isoformat()
        ok = [s for s in steps if s.success]
        return AttackResult(
            module_id=self.module_id,
            module_name=self.name,
            scenario_id=self.scenario_id,
            target=target.base_url,
            started_at=started or now,
            finished_at=now,
            total_steps=len(steps),
            successful_steps=len(ok),
            severity=self.severity.value,
            summary=summary,
            steps=steps,
        )
