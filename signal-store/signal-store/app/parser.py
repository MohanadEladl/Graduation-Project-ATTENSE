"""
parser.py – Safe wrapper that converts a raw dict into a WazuhAlert.

Isolates JSON-parsing failures from the rest of the pipeline so that
a single malformed line never brings the tail loop down.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.schema import WazuhAlert

logger = logging.getLogger("signal-mapper.parser")


def parse_alert(raw: dict) -> Optional[WazuhAlert]:
    """
    Convert *raw* (a Wazuh alert dict) into a :class:`WazuhAlert`.

    Returns ``None`` if the dict cannot be parsed, logging a warning.
    """
    try:
        return WazuhAlert.from_dict(raw)
    except Exception as exc:
        logger.warning("[parser] Cannot parse alert – %s | raw=%r", exc, str(raw)[:200])
        return None
