"""
core/models.py — Data models for the Red Team framework.

Defines the contract between modules, engine, and UI.
All modules return AttackResult. All modules declare ModuleOption.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    RECON = "Reconnaissance"
    WEB = "Web Application"
    AUTH = "Authentication"
    INJECTION = "Injection"
    FILE = "File System"
    FREESTYLE = "Freestyle"


@dataclass
class ModuleOption:
    """Describes a single configurable option for an attack module."""
    name: str
    display_name: str
    description: str
    default: Any = ""
    required: bool = False
    option_type: str = "str"      # str, int, bool, choice, file
    choices: list[str] | None = None


@dataclass
class TargetConfig:
    """Global target configuration — shared across all modules."""
    host: str = "target-agent"
    port: int = 80
    timeout: int = 10
    use_https: bool = False

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.port}"


@dataclass
class StepResult:
    """One step/probe within a module execution."""
    label: str
    url: str
    status_code: int | None = None
    latency_ms: float = 0.0
    success: bool = False
    detail: str = ""
    evidence: str = ""


@dataclass
class AttackResult:
    """Structured result returned by every module after execution."""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    module_id: str = ""
    module_name: str = ""
    scenario_id: str = ""
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_ms: float = 0.0
    total_steps: int = 0
    successful_steps: int = 0
    severity: str = Severity.INFO.value
    summary: str = ""
    steps: list[StepResult] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "module_id": self.module_id,
            "module_name": self.module_name,
            "scenario_id": self.scenario_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "total_steps": self.total_steps,
            "successful_steps": self.successful_steps,
            "severity": self.severity,
            "summary": self.summary,
            "steps": [
                {
                    "label": s.label, "url": s.url,
                    "status_code": s.status_code,
                    "latency_ms": s.latency_ms,
                    "success": s.success,
                    "detail": s.detail,
                }
                for s in self.steps
            ],
            "error": self.error,
        }
