#!/usr/bin/env python3
"""
setup_wazuh.py — Wazuh Manager First-Boot Fixups
===================================================
Fixes two recurring Wazuh manager issues found while validating the Cortex
active-response responders. Neither is persisted by any repo-tracked
config — the manager's /var/ossec/etc lives in a Docker named volume with
no bind-mounted source of truth — so they need to be (re)applied whenever
that volume is fresh.

1. Log directory ownership: Docker creates named-volume mount points as
   root, but wazuh-analysisd runs as the 'wazuh' user and crash-loops
   ("Could not create directory 'logs/<x>/<year>/' ... Permission denied")
   if it can't write to logs/archives, logs/firewall, logs/alerts.
2. Active-response command bindings: ossec.conf ships with only a
   commented-out <active-response> example. API-triggered AR via the
   "!command" prefix (used by the WazuhXxx Cortex responders) doesn't
   strictly need this, but real bindings are added anyway so ar.conf gets
   generated and automatic rule-triggered AR also works.

Runs against the already-running wazuh-manager container via the Docker
Engine API over the Unix socket (exec) — /var/ossec/etc isn't directly
reachable from this script's own filesystem.

Usage: docker compose run --rm wazuh-init
Safe to re-run: skips both fixups (and the restart) if everything is
already in place.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import time

DOCKER_SOCKET = "/var/run/docker.sock"
WAZUH_CONTAINER = os.getenv("WAZUH_CONTAINER", "attense_wazuh_manager")

AR_MARKER = "<!-- ATTENSE active-response bindings -->"
AR_BLOCKS = f"""
  {AR_MARKER}
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>all</location>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>route-null</command>
    <location>all</location>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>disable-account</command>
    <location>all</location>
  </active-response>
"""

LOG_DIRS = "/var/ossec/logs/archives /var/ossec/logs/firewall /var/ossec/logs/alerts"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # wazuh-control restart can legitimately take longer than 30s.
        self.sock.settimeout(90)
        self.sock.connect(DOCKER_SOCKET)


def _docker_request(method: str, path: str, body: dict | None = None) -> dict:
    conn = _UnixHTTPConnection("localhost")
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    if resp.status >= 300:
        raise RuntimeError(f"Docker API {method} {path} -> {resp.status}: {raw.decode(errors='replace')}")
    return json.loads(raw) if raw.strip() else {}


def docker_exec(container: str, cmd: list[str]) -> tuple[int, str]:
    """Run a command inside `container` via the Docker exec API. Returns (exit_code, output)."""
    created = _docker_request(
        "POST", f"/containers/{container}/exec",
        {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True, "Tty": True},
    )
    exec_id = created["Id"]

    conn = _UnixHTTPConnection("localhost")
    conn.request(
        "POST", f"/exec/{exec_id}/start",
        body=json.dumps({"Detach": False, "Tty": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    output = resp.read().decode(errors="replace")
    conn.close()

    info = _docker_request("GET", f"/exec/{exec_id}/json")
    return info.get("ExitCode", -1), output


def _wait_for_container(max_wait: int = 120) -> None:
    print(f"⏳ Waiting for {WAZUH_CONTAINER} to be running …", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            info = _docker_request("GET", f"/containers/{WAZUH_CONTAINER}/json")
            if info.get("State", {}).get("Running"):
                print(" ✅ running!")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print()
    sys.exit(f"❌ {WAZUH_CONTAINER} did not start in time.")


def step_check_already_healthy() -> bool:
    """Returns True if analysisd is already running AND bindings already exist."""
    _, status_out = docker_exec(WAZUH_CONTAINER, ["/var/ossec/bin/wazuh-control", "status"])
    analysisd_ok = "wazuh-analysisd is running" in status_out
    marker_code, _ = docker_exec(WAZUH_CONTAINER, ["grep", "-q", AR_MARKER, "/var/ossec/etc/ossec.conf"])
    return analysisd_ok and marker_code == 0


def step_fix_log_ownership() -> None:
    print("\n🔧 Step 1: Fix log directory ownership (archives, firewall, alerts) …")
    # mkdir -p first: on a genuinely fresh container these may not exist yet
    # (only logs/alerts is a named volume; archives/firewall are created by
    # Wazuh's own startup sequence, which can race with this script).
    code, out = docker_exec(WAZUH_CONTAINER, [
        "bash", "-c",
        f"mkdir -p {LOG_DIRS} && chown -R wazuh:wazuh {LOG_DIRS} && chmod -R 750 {LOG_DIRS}",
    ])
    if code == 0:
        print("   ✅ Ownership fixed.")
    else:
        print(f"   ⚠️  chown/chmod exited {code}: {out.strip()}")


def step_ensure_active_response_bindings() -> bool:
    print("\n🔫 Step 2: Ensure active-response command bindings exist …")
    code, _ = docker_exec(WAZUH_CONTAINER, ["grep", "-q", AR_MARKER, "/var/ossec/etc/ossec.conf"])
    if code == 0:
        print("   ✅ Already present — skipping.")
        return False

    patch_script = f'''
path = "/var/ossec/etc/ossec.conf"
content = open(path).read()
block = """{AR_BLOCKS}"""
content = content.replace("</ossec_config>", block + "\\n</ossec_config>")
open(path, "w").write(content)
print("patched")
'''
    code, out = docker_exec(WAZUH_CONTAINER, ["python3", "-c", patch_script])
    if code == 0:
        print("   ✅ Bindings added.")
        return True
    print(f"   ⚠️  Failed to patch ossec.conf (exit {code}): {out.strip()}")
    return False


def step_restart_wazuh() -> None:
    print("\n🔄 Step 3: Restarting Wazuh daemons …")
    code, _ = docker_exec(WAZUH_CONTAINER, ["/var/ossec/bin/wazuh-control", "restart"])
    print(f"   wazuh-control restart exited {code}")
    time.sleep(8)
    _, status_out = docker_exec(WAZUH_CONTAINER, ["/var/ossec/bin/wazuh-control", "status"])
    print(status_out)
    if "wazuh-analysisd is running" not in status_out:
        print("   ⚠️  wazuh-analysisd is still not running — check the container logs.")


def main() -> None:
    print("=" * 60)
    print("  ATTENSE — Wazuh Manager First-Boot Fixups")
    print("=" * 60)

    if not os.path.exists(DOCKER_SOCKET):
        sys.exit(f"❌ Docker socket not found at {DOCKER_SOCKET} — cannot exec into {WAZUH_CONTAINER}.")

    _wait_for_container()

    if step_check_already_healthy():
        print("\n✅ Already healthy and configured — nothing to do.")
        return

    step_fix_log_ownership()
    step_ensure_active_response_bindings()
    step_restart_wazuh()

    print("\n" + "=" * 60)
    print("Wazuh manager fixups complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
