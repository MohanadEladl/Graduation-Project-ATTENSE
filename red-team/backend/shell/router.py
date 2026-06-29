"""
backend/shell/router.py — Top-level shell state machine.

Holds the "attense > " level. When operator types `use brute_force`, promotes
into an AttackSession. When they type `back`, demotes back to main.
All output flows through a single callback so the caller (WebSocket handler)
can stream it to the browser.
"""
from __future__ import annotations

import shlex
from typing import Callable, Optional

from core.models import TargetConfig
from core.module_loader import discover_modules

from engine.session import AttackSession


BANNER = """
\033[31m  █████╗ ████████╗████████╗███████╗███╗   ██╗███████╗███████╗
 ██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔════╝
 ███████║   ██║      ██║   █████╗  ██╔██╗ ██║███████╗█████╗
 ██╔══██║   ██║      ██║   ██╔══╝  ██║╚██╗██║╚════██║██╔══╝
 ██║  ██║   ██║      ██║   ███████╗██║ ╚████║███████║███████╗
 ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝\033[0m

       Red Team Operator Console — Browser Shell
       \033[33m⚠  FOR INTERNAL LAB USE ONLY  ⚠\033[0m
"""


class ShellRouter:
    """
    One ShellRouter per connected browser tab.

    Public API:
        start()            → prints banner
        handle_line(text)  → routes a line to either top-level or active session
        snapshot()         → JSON-friendly view for the sidebar
    """

    def __init__(
        self,
        out: Callable[[str], None],
        default_host: str = "target-agent",
        default_port: int = 80,
    ) -> None:
        self._out = out
        self.modules = discover_modules("modules")
        self.target = TargetConfig(host=default_host, port=default_port)
        self.session: Optional[AttackSession] = None

    # ── helpers ───────────────────────────────────────────────────────────────
    def _print(self, s: str = "") -> None:
        self._out(s)

    def _info(self, m: str) -> None:
        self._out(f"[*] {m}")

    def _err(self, m: str) -> None:
        self._out(f"[!] {m}")

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> None:
        for line in BANNER.splitlines():
            self._print(line)
        self._info(f"Loaded {len(self.modules)} attack modules")
        self._info(f"Target → {self.target.base_url}")
        self._print()
        self._print("Type 'list' to browse modules, 'help' for commands.")
        self._print()

    # ── prompt ────────────────────────────────────────────────────────────────
    def prompt(self) -> str:
        if self.session:
            return f"\033[31mattense\033[0m(\033[33m{self.session.module.module_id}\033[0m) > "
        return "\033[31mattense\033[0m > "

    # ── dispatcher ────────────────────────────────────────────────────────────
    def handle_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        # If inside a session, delegate — but catch the 'back' signal
        if self.session:
            result = self.session.handle(line)
            if result == "back":
                self._info(f"Closing session [{self.session.module.module_id}]")
                self.session = None
            return

        # Top-level commands
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self._err(f"Parse error: {exc}")
            return

        cmd = parts[0].lower()
        args = parts[1:]

        handler = {
            "list":    self._cmd_list,
            "ls":      self._cmd_list,
            "modules": self._cmd_list,
            "use":     self._cmd_use,
            "target":  self._cmd_target,
            "set":     self._cmd_set_target,
            "help":    self._cmd_help,
            "?":       self._cmd_help,
            "clear":   self._cmd_clear,
            "cls":     self._cmd_clear,
        }.get(cmd)

        if handler is None:
            self._err(f"Unknown command: {cmd!r}. Type 'help'.")
            return
        handler(args)

    # ── top-level commands ────────────────────────────────────────────────────
    def _cmd_help(self, _a) -> None:
        self._print()
        self._print("  Top-level commands:")
        self._print("  ──────────────────────────────────────────────────────")
        self._print("  list                     Show available attack modules")
        self._print("  use <module_id>          Enter an attack session")
        self._print("  target                   Show current target host:port")
        self._print("  set target <host> [port] Change the target")
        self._print("  clear                    Clear the screen")
        self._print("  help                     This help")
        self._print()

    def _cmd_list(self, _a) -> None:
        sorted_mods = sorted(self.modules.values(), key=lambda m: m.module_id)
        self._print()
        self._print(f"  {'ID':<16}{'NAME':<28}{'SCENARIO':<12}SEVERITY")
        self._print(f"  {'─' * 16}{'─' * 28}{'─' * 12}{'─' * 10}")
        for m in sorted_mods:
            sev = m.severity.value.upper()
            color = {"CRITICAL": "\033[35m", "HIGH": "\033[31m",
                     "MEDIUM": "\033[33m", "LOW": "\033[36m",
                     "INFO": "\033[37m"}.get(sev, "")
            self._print(
                f"  {m.module_id:<16}{m.name:<28}{m.scenario_id or '—':<12}"
                f"{color}{sev}\033[0m"
            )
        self._print()

    def _cmd_use(self, args) -> None:
        if not args:
            self._err("Usage: use <module_id>. Try 'list'.")
            return
        mod_id = args[0]
        mod = self.modules.get(mod_id)
        if mod is None:
            self._err(f"Unknown module: {mod_id!r}. Try 'list'.")
            return
        self.session = AttackSession(mod, self.target, self._out)
        self._print()
        self.session.banner()

    def _cmd_target(self, _a) -> None:
        self._info(f"Target → {self.target.base_url}")

    def _cmd_set_target(self, args) -> None:
        # set target <host> [port]
        if len(args) < 2 or args[0].lower() != "target":
            self._err("Usage: set target <host> [port]")
            return
        self.target.host = args[1]
        if len(args) >= 3:
            try:
                self.target.port = int(args[2])
            except ValueError:
                self._err("Port must be an integer")
                return
        self._info(f"Target → {self.target.base_url}")

    def _cmd_clear(self, _a) -> None:
        # ANSI clear screen + home
        self._out("\033[2J\033[H")

    # ── snapshot for sidebar ──────────────────────────────────────────────────
    def snapshot(self) -> dict:
        return {
            "target": {"host": self.target.host, "port": self.target.port},
            "module_count": len(self.modules),
            "active_session": self.session.snapshot() if self.session else None,
        }
