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
from typing import Optional

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


def build_and_write_report(
    incident_id: str, actions_dir: Optional[str] = None
) -> Optional[dict]:
    """Run the evaluation pipeline for one incident, write its markdown report
    to ``<actions_dir>/<incident_id>_report.md``, and return a result dict — or
    None if there are no events to score (run_bridge raises ValueError).

    Shared by the CLI (main, below) and the auto-on-exercise-end hook
    (core.room_manager.spin_down_room). No VERTEX env is required: the report
    generator falls back to plain text when Gemini is unavailable.
    """
    try:
        report, events = run_bridge(incident_id)
    except ValueError:
        return None

    markdown = generate(report, events)
    out_dir = actions_dir or ACTIONS_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{incident_id}_report.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    return {
        "incident_id":  incident_id,
        "final_score":  report.get("final_score"),
        "verdict":      report.get("verdict"),
        "outcome":      report.get("outcome"),
        "status":       report.get("status"),
        "report_path":  out_path,
        "markdown":     markdown,
        "event_counts": {
            "total":   len(events),
            "wazuh":   sum(1 for e in events if e.actor_type == "system"),
            "analyst": sum(1 for e in events if e.actor_type == "blue_team"),
        },
    }

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

    print("  [1/3] Loading events, scoring, and generating the report...")
    result = build_and_write_report(incident_id)
    if result is None:
        print(f"  ERROR: No events found for incident '{incident_id}'")
        sys.exit(1)

    ec = result["event_counts"]
    print(f"        {ec['total']} events loaded  "
          f"({ec['wazuh']} Wazuh / {ec['analyst']} analyst)")
    print(f"        Outcome: {result['outcome']}  |  Status: {result['status']}")
    print(f"        Score:   {result['final_score']}  |  Verdict: {result['verdict']}")

    print(f"\n  [2/3] Wrote report → {result['report_path']}")

    print(f"\n{SEP}")
    print(f"  REPORT")
    print(f"{SEP}\n")
    print(result["markdown"])
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 -m pipeline.run_pipeline <incident_id>")
        sys.exit(1)
    main(sys.argv[1])
