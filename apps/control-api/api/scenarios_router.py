"""Scenario API (Phase 6).

Serves the canonical scenario specs so frontends and backends fetch them instead
of hard-coding their own copies. Read-only and public (scenario definitions are
not secret); a change to a scenario file is reflected here without code changes.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ATTENSE_app.scenario_specs import get_scenario, load_scenarios

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


@router.get("")
def list_scenarios() -> list[dict]:
    """All scenario specs, ordered by attack_id."""
    return [spec.model_dump() for spec in load_scenarios().values()]


@router.get("/{attack_id}")
def get_scenario_spec(attack_id: str) -> dict:
    """One scenario spec by attack_id (e.g. APP-01)."""
    spec = get_scenario(attack_id)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{attack_id}'.")
    return spec.model_dump()
