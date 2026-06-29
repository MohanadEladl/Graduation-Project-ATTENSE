"""
backend/detections.py — bridge from signal-store (Wazuh alerts) to the UI.

One background task polls `GET /events` on the signal-store service,
keeps a ring buffer of the most recent detections, and fans every new
event out to all connected WebSocket subscribers.

The broker is "best-effort": if signal-store is down we just keep
retrying. No buffering on disk — the goal is live visibility in the
workspace, not an authoritative event archive (that's signal-store's
job).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("red-team.detections")

_MAX_RING = 500
_POLL_INTERVAL = 1.0  # seconds
_SIGNAL_STORE_URL = os.getenv("SIGNAL_STORE_URL", "http://signal-store:8000")


class DetectionBroker:
    """Polls signal-store and broadcasts every new event to subscribers."""

    def __init__(self, base_url: str = _SIGNAL_STORE_URL) -> None:
        self._base_url = base_url.rstrip("/")
        self._ring: list[dict] = []
        self._seen_ids: set[str] = set()
        self._subs: Dict[str, asyncio.Queue] = {}
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._last_error: Optional[str] = None
        self._last_poll: float = 0.0
        self._reachable: bool = False

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="detection-broker")
        logger.info("DetectionBroker started against %s", self._base_url)

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    # ── State accessors ──────────────────────────────────────────────────────
    def status(self) -> dict:
        return {
            "reachable":    self._reachable,
            "last_poll":    self._last_poll,
            "last_error":   self._last_error,
            "buffered":     len(self._ring),
            "subscribers":  len(self._subs),
            "source":       self._base_url,
        }

    def recent(self, *, since: Optional[float] = None, limit: int = 100) -> list[dict]:
        """Return buffered events, optionally only those after *since* (epoch sec)."""
        items = self._ring
        if since is not None:
            items = [e for e in items if _event_ts(e) >= since]
        return items[-limit:]

    # ── Subscription ─────────────────────────────────────────────────────────
    async def subscribe(self) -> tuple[str, asyncio.Queue]:
        import uuid
        sub_id = uuid.uuid4().hex[:8]
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subs[sub_id] = q
        return sub_id, q

    async def unsubscribe(self, sub_id: str) -> None:
        async with self._lock:
            self._subs.pop(sub_id, None)

    # ── Polling loop ─────────────────────────────────────────────────────────
    async def _run(self) -> None:
        # Seed the ring once so connecting subscribers get history.
        await self._bootstrap()
        while not self._stop.is_set():
            try:
                await self._poll_once()
                self._reachable = True
                self._last_error = None
            except Exception as exc:  # noqa: BLE001
                self._reachable = False
                self._last_error = str(exc)
                logger.debug("signal-store poll failed: %s", exc)
            self._last_poll = time.time()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    def _fetch_sync(self) -> list[dict]:
        r = requests.get(f"{self._base_url}/events",
                         params={"limit": _MAX_RING}, timeout=2.0)
        r.raise_for_status()
        data = r.json() or []
        return data if isinstance(data, list) else []

    async def _bootstrap(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            events = await loop.run_in_executor(None, self._fetch_sync)
            for ev in events:
                self._record(ev, broadcast=False)
            self._reachable = True
            logger.info("DetectionBroker bootstrap: %d events", len(events))
        except Exception as exc:  # noqa: BLE001
            self._last_error = str(exc)
            logger.info("DetectionBroker bootstrap failed: %s", exc)

    async def _poll_once(self) -> None:
        loop = asyncio.get_running_loop()
        events = await loop.run_in_executor(None, self._fetch_sync)
        new = [e for e in events if _event_id(e) not in self._seen_ids]
        if not new:
            return
        for ev in new:
            self._record(ev, broadcast=True)

    # ── Internal ─────────────────────────────────────────────────────────────
    def _record(self, ev: dict, *, broadcast: bool) -> None:
        eid = _event_id(ev)
        if not eid or eid in self._seen_ids:
            return
        self._seen_ids.add(eid)
        self._ring.append(ev)
        if len(self._ring) > _MAX_RING:
            drop = self._ring[: len(self._ring) - _MAX_RING]
            self._ring = self._ring[-_MAX_RING:]
            for d in drop:
                self._seen_ids.discard(_event_id(d))
        if broadcast:
            for q in list(self._subs.values()):
                try:
                    q.put_nowait(ev)
                except asyncio.QueueFull:
                    pass


# ── utilities ────────────────────────────────────────────────────────────────
def _event_id(ev: Any) -> str:
    if not isinstance(ev, dict):
        return ""
    return str(ev.get("event_id") or ev.get("id") or "")


def _event_ts(ev: Any) -> float:
    """Best-effort epoch-seconds extraction from a StandardEvent dict."""
    if not isinstance(ev, dict):
        return 0.0
    raw = ev.get("timestamp")
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        # ISO-8601 from signal-store; datetime.fromisoformat handles the suffix.
        try:
            from datetime import datetime
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0
