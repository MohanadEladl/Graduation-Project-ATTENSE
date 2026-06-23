"""Canonical scenario specification model (Phase 6)."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScenarioSpec(BaseModel):
    """The canonical definition of one attack scenario."""

    model_config = ConfigDict(extra="forbid")

    spec_version: str = "1.0"
    attack_id: str = Field(..., examples=["APP-01"])
    module_id: str = Field(..., description="Red-team module id.", examples=["xss"])
    name: str = Field(..., description="Human attack name.")
    description: str
    target_path: str = Field(..., description="Vulnerable path on the target.")
    owasp: Optional[str] = None
    severity: Optional[str] = None
    attack_steps: List[str] = Field(default_factory=list, description="Permitted attack chain.")
    impact: List[str] = Field(default_factory=list)
    defense_checkpoints: List[str] = Field(default_factory=list)
    required_tools: List[str] = Field(default_factory=list)
