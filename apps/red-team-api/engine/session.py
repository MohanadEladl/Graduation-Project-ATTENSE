"""
engine/session.py — AttackSession: one active attack module under operator control.

Workflow: select module → set options → show steps → start
→ watch live output → see result. All commands route through handle().
"""
from __future__ import annotations

import os
import shlex
import threading
from typing import Callable, Optional

from core.base_module import BaseModule
from core.engine import Engine
from core.logger import LogManager
from core.models import AttackResult, TargetConfig

from engine.timer import Timer


# Default step templates for modules that don't declare their own.
_DEFAULT_STEPS = [
    {"title": "Prepare request", "hint": "Build HTTP session with lab UA", "expected": "Session ready"},
    {"title": "Execute probe", "hint": "Send payloads against endpoint", "expected": "Response captured"},
    {"title": "Analyze response", "hint": "Match indicators in body/status", "expected": "Verdict produced"},
]


class AttackSession:
    """
    Single-module interactive session.

    Owns:
      - reference to the chosen BaseModule instance
      - operator-provided option values
      - a TargetConfig (host/port)
      - a Timer
      - the latest AttackResult (after start completes)
      - state: 'idle' | 'running' | 'completed' | 'error'

    Commands (one per text line from the shell):
      set <option> <value>
      unset <option>
      show options | show steps | show info
      start
      status
      help
      back     → handled by the parent router
    """

    def __init__(
        self,
        module: BaseModule,
        target: TargetConfig,
        out: Callable[[str], None],
    ) -> None:
        self.module = module
        self.target = target
        self._out = out
        self.options: dict = {}
        self.timer = Timer()
        self.state: str = "idle"
        self.result: Optional[AttackResult] = None
        self._run_lock = threading.Lock()

        # Pre-fill defaults from module metadata
        for o in module.options():
            if o.default not in ("", None):
                self.options[o.name] = o.default

    # ── Output helpers ────────────────────────────────────────────────────────
    def _print(self, line: str = "") -> None:
        self._out(line)

    def _info(self, msg: str) -> None:
        self._out(f"[*] {msg}")

    def _ok(self, msg: str) -> None:
        self._out(f"[+] {msg}")

    def _err(self, msg: str) -> None:
        self._out(f"[!] {msg}")

    # ── Banner shown on entering the session ──────────────────────────────────
    def banner(self) -> None:
        self._info(f"Module   : {self.module.name}")
        self._info(f"Scenario : {self.module.scenario_id or '—'}")
        self._info(f"Severity : {self.module.severity.value.upper()}")
        self._info(f"Target   : {self.target.base_url}")
        self._print()
        self._print("Type 'help' for commands, 'show steps' to see the plan.")
        self._print()

    # ── Main command dispatcher ───────────────────────────────────────────────
    def handle(self, line: str) -> str:
        """
        Process one command line from the operator.
        Returns a control token: 'stay' (continue session) or 'back' (exit to main).
        """
        line = line.strip()
        if not line:
            return "stay"

        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self._err(f"Parse error: {exc}")
            return "stay"

        cmd = parts[0].lower()
        args = parts[1:]

        handler = {
            "help":    self._cmd_help,
            "?":       self._cmd_help,
            "show":    self._cmd_show,
            "set":     self._cmd_set,
            "unset":   self._cmd_unset,
            "start":   self._cmd_start_guided,
            "run":     self._cmd_start_guided,
            "execute": self._cmd_execute,
            "status":  self._cmd_status,
            "info":    lambda _a: self._show_info(),
            "back":    lambda _a: "back",
            "exit":    lambda _a: "back",
        }.get(cmd)

        if handler is None:
            self._err(f"Unknown command: {cmd!r}. Type 'help'.")
            return "stay"
        return handler(args) or "stay"

    # ── Commands ──────────────────────────────────────────────────────────────
    def _cmd_help(self, _args) -> None:
        self._print()
        self._print("  Commands inside a module session:")
        self._print("  ─────────────────────────────────────────────────────")
        self._print("  show info            Module overview")
        self._print("  show options         Current option values")
        self._print("  show steps           Attack plan + hints")
        self._print("  set <opt> <value>    Assign an option")
        self._print("  unset <opt>          Clear an option")
        self._print("  start                Begin guided mission (timer)")
        self._print("  execute              Run the attack against target")
        self._print("  status               Live status + elapsed time")
        self._print("  back                 Return to main shell")
        self._print()

    def _cmd_show(self, args) -> None:
        if not args:
            self._err("Usage: show options | show steps | show info")
            return
        what = args[0].lower()
        if what == "options":
            self._show_options()
        elif what == "steps":
            self._show_steps()
        elif what == "info":
            self._show_info()
        else:
            self._err(f"Unknown 'show' subject: {what!r}")

    def _show_info(self) -> None:
        m = self.module
        self._print()
        self._print(f"  {m.name}")
        self._print(f"  {'─' * len(m.name)}")
        if m.description:
            # Word-wrap at ~70 chars
            words = m.description.split()
            line = "  "
            for w in words:
                if len(line) + len(w) > 72:
                    self._print(line)
                    line = "  "
                line += w + " "
            if line.strip():
                self._print(line)
        self._print()
        self._print(f"  Category : {m.category.value}")
        self._print(f"  Scenario : {m.scenario_id or '—'}")
        self._print(f"  Severity : {m.severity.value.upper()}")
        self._print()

    def _show_options(self) -> None:
        rows = []
        for o in self.module.options():
            val = self.options.get(o.name, "")
            rows.append((o.name, str(val) if val != "" else "—",
                         "yes" if o.required else "no", o.description))
        rows.append(("TARGET_HOST", self.target.host, "yes", "Target host"))
        rows.append(("TARGET_PORT", str(self.target.port), "yes", "Target port"))

        self._print()
        self._print(f"  {'OPTION':<16}{'VALUE':<22}{'REQUIRED':<10}DESCRIPTION")
        self._print(f"  {'─' * 16}{'─' * 22}{'─' * 10}{'─' * 40}")
        for name, val, req, desc in rows:
            desc_trunc = (desc[:38] + "..") if len(desc) > 40 else desc
            self._print(f"  {name:<16}{val:<22}{req:<10}{desc_trunc}")
        self._print()

    def _show_steps(self) -> None:
        steps = getattr(self.module, "steps", None) or _DEFAULT_STEPS
        self._print()
        for i, s in enumerate(steps, 1):
            self._print(f"  Step {i}  {s['title']}")
            self._print(f"          Hint     : {s['hint']}")
            self._print(f"          Expected : {s['expected']}")
            self._print()

    def _cmd_set(self, args) -> None:
        if len(args) < 2:
            self._err("Usage: set <option> <value>")
            return
        key = args[0]
        val = " ".join(args[1:])

        # Special target options
        if key.upper() == "TARGET_HOST":
            self.target.host = val
            self._ok(f"TARGET_HOST → {val}")
            return
        if key.upper() == "TARGET_PORT":
            try:
                self.target.port = int(val)
                self._ok(f"TARGET_PORT → {val}")
            except ValueError:
                self._err("TARGET_PORT must be an integer")
            return

        # Module-defined option
        valid_names = {o.name for o in self.module.options()}
        if key not in valid_names:
            self._err(f"Unknown option: {key!r}. Try 'show options'.")
            return
        self.options[key] = val
        self._ok(f"{key} → {val}")

    def _cmd_unset(self, args) -> None:
        if not args:
            self._err("Usage: unset <option>")
            return
        key = args[0]
        if key in self.options:
            del self.options[key]
            self._ok(f"{key} cleared")
        else:
            self._err(f"{key} is not set")

    def _cmd_start_guided(self, _args) -> None:
        """Begin guided mission — starts the timer but does NOT execute the attack."""
        if self.state == "running":
            self._err("An attack is already running.")
            return
        if self.state == "completed":
            self._info("This mission is already completed.")
            return
        if not self.timer.started_at:
            self.timer.start()
        self._print()
        self._ok("Guided mission started — timer is running.")
        self._print()
        self._print("  Review the attack plan:")
        self._print("    show info       Module overview")
        self._print("    show options    Current options")
        self._print("    show steps      Step-by-step plan")
        self._print()
        self._info("When you are ready, type 'execute' to launch the attack.")
        self._print()

    def _cmd_execute(self, _args) -> None:
        """Actually execute the attack module against the target."""
        if self.state == "running":
            self._err("An attack is already running. Wait or restart the session.")
            return

        # Validate
        err = self.module.validate(self.options, self.target)
        if err:
            self._err(err)
            return

        # Wire live log stream from the Engine's LogManager to our output
        log_mgr = LogManager()
        log_mgr.subscribe(lambda line: self._out(line))
        engine = Engine({self.module.module_id: self.module}, log_mgr)

        self.state = "running"
        if not self.timer.started_at:
            self.timer.start()
        self._info(f"Executing {self.module.name} against {self.target.base_url}...")
        self._print()

        try:
            self.result = engine.run_module(
                self.module.module_id, self.target, dict(self.options)
            )
            self.timer.stop()
            if self.result.error:
                self.state = "error"
                self._err(f"Attack failed: {self.result.error}")
            else:
                self.state = "completed"
                self._print()
                self._ok(
                    f"Complete — {self.result.successful_steps}/"
                    f"{self.result.total_steps} steps OK | "
                    f"{self.result.duration_ms:.0f}ms"
                )
                self._info(f"Summary: {self.result.summary}")
                self._info(f"Elapsed: {self.timer.elapsed()}")
        except Exception as exc:  # noqa: BLE001
            self.timer.stop()
            self.state = "error"
            self._err(f"Unexpected error: {exc}")

    def _cmd_status(self, _args) -> None:
        self._print()
        self._print(f"  Module    : {self.module.name}")
        self._print(f"  State     : {self.state.upper()}")
        if self.timer.started_at:
            self._print(f"  Started   : {self.timer.started_at}")
        if self.timer.stopped_at:
            self._print(f"  Ended     : {self.timer.stopped_at}")
        if self.timer.started_at:
            self._print(f"  Duration  : {self.timer.elapsed()}")
        if self.result:
            self._print(f"  Result    : {self.result.summary or '—'}")
            self._print(
                f"  Steps OK  : {self.result.successful_steps} / "
                f"{self.result.total_steps}"
            )
        self._print()

    # ── Snapshot for frontend sidebar ─────────────────────────────────────────
    def snapshot(self) -> dict:
        return {
            "module_id":   self.module.module_id,
            "module_name": self.module.name,
            "state":       self.state,
            "started_at":  self.timer.started_at,
            "stopped_at":  self.timer.stopped_at,
            "elapsed":     self.timer.elapsed() if self.timer.started_at else None,
            "result":      self.result.to_dict() if self.result else None,
        }
