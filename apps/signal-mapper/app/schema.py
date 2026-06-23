"""
schema.py – StandardEvent schema for ATTENSE Signal Mapper.

This is the canonical output model.  Every Wazuh alert that passes through
the mapper is converted to a StandardEvent before being emitted.
"""
from __future__ import annotations

import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ── Wazuh input models (loosely typed, defaults everywhere) ──────────────────

class WazuhRule(BaseModel):
    id: str = ""
    level: int = 0
    description: str = ""
    groups: list[str] = Field(default_factory=list)
    mitre: Optional[dict[str, Any]] = None


class WazuhAgent(BaseModel):
    id: str = ""
    name: str = ""
    ip: str = ""


class WazuhData(BaseModel):
    srcip: str = ""
    dstip: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class WazuhAlert(BaseModel):
    """Parsed, normalised view of a single Wazuh alert object."""
    timestamp: str = ""
    rule: WazuhRule = Field(default_factory=WazuhRule)
    agent: WazuhAgent = Field(default_factory=WazuhAgent)
    location: str = ""
    full_log: str = ""
    data: WazuhData = Field(default_factory=WazuhData)
    # The original raw dict – excluded from serialisation
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "WazuhAlert":
        rule_raw = d.get("rule", {}) if isinstance(d.get("rule"), dict) else {}
        agent_raw = d.get("agent", {}) if isinstance(d.get("agent"), dict) else {}
        data_raw = d.get("data", {}) if isinstance(d.get("data"), dict) else {}

        known_data_keys = {"srcip", "dstip"}
        extra_data = {k: v for k, v in data_raw.items() if k not in known_data_keys}

        return cls(
            timestamp=str(d.get("timestamp", "")),
            rule=WazuhRule(
                id=str(rule_raw.get("id", "")),
                level=int(rule_raw.get("level", 0) or 0),
                description=str(rule_raw.get("description", "")),
                groups=list(rule_raw.get("groups", [])),
                mitre=rule_raw.get("mitre"),
            ),
            agent=WazuhAgent(
                id=str(agent_raw.get("id", "")),
                name=str(agent_raw.get("name", "")),
                ip=str(agent_raw.get("ip", "")),
            ),
            location=str(d.get("location", "")),
            full_log=str(d.get("full_log", "")),
            data=WazuhData(
                srcip=str(data_raw.get("srcip", "")),
                dstip=str(data_raw.get("dstip", "")),
                extra=extra_data,
            ),
            raw=d,
        )


# ── ATTENSE StandardEvent output schema ──────────────────────────────────────
# DEPRECATED: StandardEvent is replaced by the canonical Event class 
# in ATTENSE_app.events.event.

