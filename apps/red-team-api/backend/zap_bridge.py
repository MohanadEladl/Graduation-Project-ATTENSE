"""
backend/zap_bridge.py — bridge from ZAP's alerts queue to the scoring engine.

Structurally mirrors backend/detections.py::DetectionBroker (background
asyncio task, bootstrap-without-broadcast, _seen_ids dedup). Polls ZAP's
ALERTS endpoint (vulnerabilities ZAP's own passive/active scanning flagged),
not the raw-traffic endpoint operator_api.py::get_zap_history() already
polls (/JSON/core/view/messages/) -- alerts and traffic are different ZAP
APIs answering different questions.

Without this, freestyle (open_lab) sessions are invisible to the scoring
engine: scripted modules report themselves via core/engine.py, but freestyle
attacks have no module-side reporting at all -- ZAP's own findings are the
only signal.

Field shapes confirmed live against a populated ZAP alert (id, risk, alert,
confidence, url, evidence, cweid, wascid, etc.) before writing this.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any, Optional

import requests

from core import event_sink
from backend.session_manager import SessionManager

logger = logging.getLogger("red-team.zap_bridge")

_POLL_INTERVAL = 5.0  # seconds -- ZAP alerts aren't latency-sensitive like live log tailing
_FETCH_COUNT = 200
_OPEN_LAB_MODULE_ID = "open_lab"

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
# No baked-in default key (check-secrets requires ZAP_API_KEY and rejects the
# stock "attense-lab-key"); empty fails loudly rather than using a known key.
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")


def _outcome_for_alert(risk: str) -> str:
    """Map ZAP's risk rating onto the Event schema's outcome enum. Every
    alert here represents something ZAP actually found, so there's no
    'failure' case -- only how significant the finding is."""
    return "success" if risk in ("High", "Medium") else "partial"


class ZapBridge:
    """Polls ZAP's alerts queue and reports new alerts as malicious_action_executed."""

    def __init__(
        self,
        sessions: SessionManager,
        base_url: str = ZAP_API_URL,
        api_key: str = ZAP_API_KEY,
    ) -> None:
        self._sessions = sessions
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._seen_ids: set[str] = set()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._last_error: Optional[str] = None
        self._last_poll: float = 0.0
        self._reachable: bool = False
        self._emitted_count: int = 0
        self._last_multi_session_warn: float = 0.0

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="zap-bridge")
        logger.info("ZapBridge started against %s", self._base_url)

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    # ── State accessor ───────────────────────────────────────────────────────
    def status(self) -> dict:
        return {
            "reachable":      self._reachable,
            "last_poll":      self._last_poll,
            "last_error":     self._last_error,
            "seen_alerts":    len(self._seen_ids),
            "emitted_events": self._emitted_count,
            "source":         self._base_url,
        }

    # ── Polling loop ─────────────────────────────────────────────────────────
    async def _run(self) -> None:
        # Seed _seen_ids without emitting -- pre-existing alerts (from before
        # the bridge started, or from scripted modules' own traffic) aren't
        # replayed as freestyle events. Same rationale as DetectionBroker.
        await self._bootstrap()
        while not self._stop.is_set():
            try:
                await self._poll_once()
                self._reachable = True
                self._last_error = None
            except Exception as exc:  # noqa: BLE001
                self._reachable = False
                self._last_error = str(exc)
                logger.debug("ZAP alerts poll failed: %s", exc)
            self._last_poll = time.time()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    def _fetch_sync(self) -> list[dict]:
        r = requests.get(
            f"{self._base_url}/JSON/alert/view/alerts/",
            params={"apikey": self._api_key, "baseurl": "", "start": 0, "count": _FETCH_COUNT},
            timeout=5.0,
        )
        r.raise_for_status()
        data = r.json() or {}
        alerts = data.get("alerts", [])
        return alerts if isinstance(alerts, list) else []

    async def _bootstrap(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            alerts = await loop.run_in_executor(None, self._fetch_sync)
            for alert in alerts:
                aid = _alert_id(alert)
                if aid:
                    self._seen_ids.add(aid)
            self._reachable = True
            logger.info("ZapBridge bootstrap: %d pre-existing alerts seeded (not emitted)", len(alerts))
        except Exception as exc:  # noqa: BLE001
            self._last_error = str(exc)
            logger.info("ZapBridge bootstrap failed: %s", exc)

    async def _poll_once(self) -> None:
        loop = asyncio.get_running_loop()
        alerts = await loop.run_in_executor(None, self._fetch_sync)
        new = [a for a in alerts if _alert_id(a) and _alert_id(a) not in self._seen_ids]
        if not new:
            return
        incident_id, actor_id = self._resolve_target_session()
        for alert in new:
            aid = _alert_id(alert)
            self._seen_ids.add(aid)
            self._emit(alert, incident_id, actor_id)

    # ── Context resolution ───────────────────────────────────────────────────
    def _resolve_target_session(self) -> tuple[Optional[str], Optional[str]]:
        """Most recently created open_lab session's incident_id/actor_id, or
        the env var INCIDENT_ID fallback if none exist (today's behavior)."""
        open_lab_sessions = [
            s for s in self._sessions.list() if s.get("module_id") == _OPEN_LAB_MODULE_ID
        ]
        if not open_lab_sessions:
            return os.environ.get("INCIDENT_ID"), "redteam-operator"

        if len(open_lab_sessions) > 1:
            now = time.time()
            if now - self._last_multi_session_warn > _POLL_INTERVAL:
                logger.warning(
                    "%d concurrent open_lab sessions active -- tagging alerts "
                    "to the most recently created one (single-AttackBox lab; "
                    "this should be rare).",
                    len(open_lab_sessions),
                )
                self._last_multi_session_warn = now

        most_recent = max(open_lab_sessions, key=lambda s: s.get("created_at") or 0)
        incident_id = most_recent.get("incident_id") or os.environ.get("INCIDENT_ID")
        actor_id = most_recent.get("actor_id") or "redteam-operator"
        return incident_id, actor_id

    def _emit(self, alert: dict, incident_id: Optional[str], actor_id: Optional[str]) -> None:
        if not incident_id:
            logger.warning(
                "No incident_id available (no joined room, no env var INCIDENT_ID) -- "
                "skipping ZAP alert %r.", alert.get("alert"),
            )
            return

        risk = str(alert.get("risk", "Informational"))
        event_sink.post_malicious_action_event(
            event_id=uuid.uuid4().hex[:8],
            incident_id=incident_id,
            scenario_id="OPEN-LAB",
            actor_id=actor_id or "redteam-operator",
            target_id=str(alert.get("url") or "http://target-agent"),
            outcome=_outcome_for_alert(risk),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            metadata={"source": "zap_alert", "zap_alert": alert},
            log_fn=logger.warning,
        )
        self._emitted_count += 1


def _alert_id(alert: Any) -> str:
    if not isinstance(alert, dict):
        return ""
    return str(alert.get("id") or "")
