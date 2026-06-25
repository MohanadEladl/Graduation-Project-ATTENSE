"""
modules/open_lab.py — Open Lab: unscripted freestyle exploration.

No prescribed attack path. The operator gets AttackBox + ZAP and explores
target-agent however they want. This module's own execute() is just a
reachability check, not the real attack — actual scoring comes from
backend/zap_bridge.py polling ZAP's alerts queue while this session is open
and emitting malicious_action_executed for anything ZAP flags.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    TargetConfig,
)


class OpenLabModule(BaseModule):
    module_id = "open_lab"
    name = "Open Lab — Freestyle"
    description = (
        "No prescribed attack path. Use the AttackBox terminal and ZAP proxy "
        "freely against target-agent. Actions are scored via the ZAP-alerts "
        "bridge, not by this module's own execute()."
    )
    category = Category.FREESTYLE
    scenario_id = "OPEN-LAB"
    severity = Severity.INFO
    # No `steps` attribute on purpose — there is no scripted plan. The shell's
    # `show steps` falls back to the generic 3-step placeholder, which is fine.

    def options(self) -> list[ModuleOption]:
        return []

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        self._log(log_fn, "Open lab session starting — checking target reachability...")
        step = self._get(target.base_url + "/", label="open-lab-reachability", timeout=target.timeout)

        if step.success:
            summary = (
                "Open lab session ready — target reachable. Use AttackBox + ZAP "
                "freely; the ZAP-alerts bridge scores whatever you find."
            )
        else:
            summary = "Open lab session ready — target unreachable; check target-agent."

        self._log(log_fn, summary)
        return self._make_result(target, [step], summary=summary, started=started)
