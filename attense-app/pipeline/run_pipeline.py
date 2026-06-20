"""
pipeline/run_pipeline.py — Orchestrator

Usage (from inside the container):
    python3 -m pipeline.run_pipeline <incident_id>

Output:
    /attense/actions/<incident_id>_report.md

Steps:
    1. bridge.run_bridge(incident_id)  → (report_dict, events)
    2. report_generator.generate(report_dict, events)  → markdown string
    3. Write markdown to /attense/actions/<incident_id>_report.md
    4. Print report to stdout
"""

import os
import sys

# Ensure both /app (ATTENSE_app) and /app/pipeline are importable
_HERE = os.path.dirname(os.path.abspath(__file__))
_APP  = os.path.dirname(_HERE)
for _p in (_APP, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pipeline.bridge           import run_bridge
from pipeline.report_generator import generate

ACTIONS_DIR = os.environ.get("ACTIONS_LOG_DIR", "/attense/actions")
SEP = "=" * 65

_ENV_HINT = "export $(cat attense-app/pipeline/.env | xargs)"

_REQUIRED_ENV = [
    ("VERTEX_PROJECT_ID", "GCP project ID for Vertex AI"),
    ("VERTEX_MODEL",      "Gemini model name (e.g. gemini-3.5-flash)"),
]


def _check_env() -> None:
    missing = [
        (var, desc) for var, desc in _REQUIRED_ENV
        if not os.environ.get(var, "").strip()
    ]
    if not missing:
        return
    lines = ["", "  MISSING REQUIRED ENVIRONMENT VARIABLES", "  " + "-" * 44]
    for var, desc in missing:
        lines.append(f"  {var}  —  {desc}")
    lines += [
        "",
        f"  Run this before starting the pipeline:",
        f"    {_ENV_HINT}",
        "",
    ]
    print("\n".join(lines), file=sys.stderr)
    sys.exit(1)


def main(incident_id: str) -> None:
    _check_env()

    print(f"\n{SEP}")
    print(f"  ATTENSE EVALUATION PIPELINE  |  {incident_id}")
    print(f"{SEP}\n")

    print("  [1/3] Loading events and building incident model...")
    try:
        report, events = run_bridge(incident_id)
    except ValueError as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)

    wazuh_n   = sum(1 for e in events if e.actor_type == "system")
    analyst_n = sum(1 for e in events if e.actor_type == "blue_team")
    print(f"        {len(events)} events loaded  "
          f"({wazuh_n} Wazuh / {analyst_n} analyst)")
    print(f"        Outcome: {report['outcome']}  |  Status: {report['status']}")

    print("\n  [2/3] Generating markdown report via Gemini...")
    markdown = generate(report, events)

    out_path = os.path.join(ACTIONS_DIR, f"{incident_id}_report.md")
    print(f"\n  [3/3] Writing report → {out_path}")
    os.makedirs(ACTIONS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    print(f"\n{SEP}")
    print(f"  REPORT")
    print(f"{SEP}\n")
    print(markdown)
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 -m pipeline.run_pipeline <incident_id>")
        sys.exit(1)
    main(sys.argv[1])
