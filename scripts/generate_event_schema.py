"""Generate the JSON Schema for the canonical event contract from the model.

Phase 2 of ATTENSE_Refactoring_Optimization_Report.md: "Generate the JSON Schema
from the model." `StandardEvent` is the single source of truth; the committed
`ATTENSE_app/events/standard_event.schema.json` is a generated artifact, never
hand-edited. Run this whenever the model changes (and in CI to detect drift):

    python scripts/generate_event_schema.py            # write the schema file
    python scripts/generate_event_schema.py --check     # fail if out of date

The `--check` mode is structural-only-friendly: it regenerates and compares, so
keep regeneration deterministic (it is: model_json_schema() is stable input).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_CORE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "packages", "attense-core")
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from attense_core.models.standard_event import StandardEvent  # noqa: E402

SCHEMA_PATH = os.path.join(
    _CORE_ROOT, "attense_core", "models", "standard_event.schema.json"
)


def render() -> str:
    schema = StandardEvent.model_json_schema()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed schema is out of date",
    )
    args = parser.parse_args()

    rendered = render()

    if args.check:
        if not os.path.exists(SCHEMA_PATH):
            print(f"schema file missing: {SCHEMA_PATH}", file=sys.stderr)
            return 1
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            current = fh.read()
        if current != rendered:
            print(
                "standard_event.schema.json is out of date; "
                "run: python scripts/generate_event_schema.py",
                file=sys.stderr,
            )
            return 1
        print("standard_event.schema.json is up to date.")
        return 0

    with open(SCHEMA_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(rendered)
    print(f"wrote {SCHEMA_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
