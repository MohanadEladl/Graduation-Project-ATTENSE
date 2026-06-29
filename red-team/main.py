"""
main.py — CLI fallback (v3).

The primary operator interface is now the browser-based shell served by the
red-team-frontend container. This CLI remains available inside the backend
container for SSH sessions or debugging:

    docker exec -it attense_red_team_backend python main.py --list
    docker exec -it attense_red_team_backend python main.py --module brute_force
"""
from __future__ import annotations
import argparse, os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.engine import Engine
from core.logger import LogManager
from core.models import TargetConfig
from core.module_loader import discover_modules


def main() -> int:
    p = argparse.ArgumentParser(description="ATTENSE Red Team CLI fallback")
    p.add_argument("--module", "-m")
    p.add_argument("--all",   action="store_true")
    p.add_argument("--list",  action="store_true")
    p.add_argument("--host",  default=os.getenv("TARGET_HOST", "target-agent"))
    p.add_argument("--port",  type=int, default=int(os.getenv("TARGET_PORT", "80")))
    args = p.parse_args()

    modules = discover_modules("modules")
    sorted_mods = sorted(modules.values(), key=lambda m: m.module_id)

    if args.list:
        for m in sorted_mods:
            print(f"  {m.module_id:<16} {m.name:<28} {m.scenario_id:<12} {m.severity.value.upper()}")
        return 0

    log_mgr = LogManager()
    engine  = Engine(modules, log_mgr)
    target  = TargetConfig(host=args.host, port=args.port)

    if args.module:
        if args.module not in modules:
            print(f"Unknown module: {args.module!r}", file=sys.stderr)
            return 2
        result = engine.run_module(args.module, target, {})
        return 0 if result.error is None else 1

    if args.all:
        rc = 0
        for m in sorted_mods:
            result = engine.run_module(m.module_id, target, {})
            if result.error: rc = 1
        return rc

    # No args → tell the operator about the web shell
    print("\n  The primary interface is now the web shell at http://localhost:3000")
    print("  For CLI use:  python main.py --list")
    print("                python main.py --module <id>")
    print("                python main.py --all\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
