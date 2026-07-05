#!/usr/bin/env python3
"""Auto-run the red-team -> Blue Team cycle once the stack is healthy.

Runs once per `docker compose up` (the service uses restart: "no"). It waits for
the red-team backend to report healthy, then for each module in AUTO_MODULES it
creates a session, starts it, and executes it. `SessionManager.execute()` emits a
`malicious_action_executed` event to the control API, which auto-creates the Blue
Team room (incidents_router.ingest_event -> room_manager.ensure_room_for_incident)
and binds signal-store so Wazuh detections flow into that room. The net effect:
the operator no longer has to manually create a room or launch an attack -- the
red-team -> Blue Team pipeline completes by itself on startup.

Stdlib only (urllib): no third-party deps so it can run in any Python image.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

REDTEAM_URL = os.getenv("REDTEAM_URL", "http://red-team-backend:8000").rstrip("/")
AUTO_MODULES = [m.strip() for m in os.getenv(
    "AUTO_MODULES", "xss,cmd_injection,dir_traversal").split(",") if m.strip()]
AUTO_MODE = os.getenv("AUTO_MODE", "lab")
WAIT_SECONDS = int(os.getenv("AUTO_WAIT_SECONDS", "240"))
SETTLE_SECONDS = int(os.getenv("AUTO_SETTLE_SECONDS", "10"))
BETWEEN_SECONDS = int(os.getenv("AUTO_BETWEEN_SECONDS", "6"))


def _call(method: str, path: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        REDTEAM_URL + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)


def _wait_healthy() -> bool:
    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        try:
            status, _ = _call("GET", "/health")
            if status == 200:
                print("[auto-cycle] red-team backend healthy", flush=True)
                return True
        except Exception as exc:  # noqa: BLE001
            print(f"[auto-cycle] waiting for backend... ({exc})", flush=True)
        time.sleep(4)
    return False


def _run_module(module_id: str) -> None:
    try:
        status, resp = _call("POST", "/api/sessions",
                             {"module_id": module_id, "mode": AUTO_MODE})
        sid = resp.get("session_id") if isinstance(resp, dict) else None
        print(f"[auto-cycle] {module_id}: create={status} sid={sid}", flush=True)
        if not sid:
            return
        _call("POST", f"/api/sessions/{sid}/start")
        status, _ = _call("POST", f"/api/sessions/{sid}/execute")
        print(f"[auto-cycle] {module_id}: execute={status} (event emitted -> "
              f"Blue Team room auto-surfaces)", flush=True)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        print(f"[auto-cycle] {module_id}: HTTP {exc.code} {detail}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[auto-cycle] {module_id}: error {exc}", flush=True)


def main() -> None:
    print(f"[auto-cycle] target={REDTEAM_URL} modules={AUTO_MODULES} "
          f"mode={AUTO_MODE}", flush=True)
    if not _wait_healthy():
        print("[auto-cycle] backend not healthy in time; giving up", flush=True)
        return
    time.sleep(SETTLE_SECONDS)
    for module_id in AUTO_MODULES:
        _run_module(module_id)
        time.sleep(BETWEEN_SECONDS)
    print("[auto-cycle] done -- red-team -> Blue Team cycle fired", flush=True)


if __name__ == "__main__":
    main()
