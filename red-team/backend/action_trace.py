"""
backend/action_trace.py — Browser action capture for Phase 2 tracing.

The learner's clicks, form submits, and page-changes inside the lab-browser
iframe POST a small JSON event to /api/lab/actions.  This module is the
in-memory store + read API.

Each action looks like:
  {
    "ts":         epoch float,
    "session_id": "...",
    "kind":       "click" | "form_submit" | "page_view" | "input_focus",
    "selector":   "button#login",
    "text":       "Sign In",
    "page":       "/auth/login",
    "extra":      {...}
  }

The Report agent and the timeline endpoint both consume this stream.
"""
from __future__ import annotations
import threading
import time
from typing import Any, Dict, List, Optional

_MAX = 5000
_lock = threading.Lock()
_actions: List[Dict[str, Any]] = []


def record(
    session_id: Optional[str],
    kind: str,
    *,
    selector: Optional[str] = None,
    text: Optional[str] = None,
    page: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record a browser action. Best-effort, never raises."""
    ev = {
        "id":         len(_actions),
        "ts":         time.time(),
        "session_id": session_id or None,
        "kind":       str(kind)[:40],
        "selector":   (selector or "")[:200] or None,
        "text":       (text or "")[:200] or None,
        "page":       (page or "")[:200] or None,
        "extra":      dict(extra or {}),
    }
    with _lock:
        _actions.append(ev)
        if len(_actions) > _MAX:
            del _actions[: len(_actions) - _MAX]
    return ev


def list_actions(
    *,
    session_id: Optional[str] = None,
    since: float = 0.0,
    kind: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """Return actions filtered by session_id / since / kind."""
    with _lock:
        snap = list(_actions)
    out = [a for a in snap if a["ts"] >= since]
    if session_id:
        out = [a for a in out if a.get("session_id") == session_id]
    if kind:
        out = [a for a in out if a.get("kind") == kind]
    return out[-limit:]


def reset(session_id: Optional[str] = None) -> int:
    """Clear actions (all or for one session). Returns count removed."""
    global _actions
    with _lock:
        if session_id is None:
            n = len(_actions)
            _actions = []
            return n
        before = len(_actions)
        _actions = [a for a in _actions if a.get("session_id") != session_id]
        return before - len(_actions)
