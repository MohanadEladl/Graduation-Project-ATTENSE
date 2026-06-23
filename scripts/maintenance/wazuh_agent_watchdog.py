#!/usr/bin/env python3
"""
Wazuh agent watchdog for the ATTENSE lab.

The target-agent container is intentionally disposable, but Wazuh manager keeps
agent registrations in its own persisted volume. If the target is recreated
with a fresh local /var/ossec state while the manager still has the old record,
authd rejects enrollment as a duplicate agent name. This watchdog detects that
state and repairs it without requiring a user to run manage_agents manually.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import time

DOCKER_SOCKET = "/var/run/docker.sock"
WAZUH_CONTAINER = os.getenv("WAZUH_CONTAINER", "attense_wazuh_manager")
TARGET_CONTAINER = os.getenv("TARGET_CONTAINER", "attense_target_agent")
TARGET_AGENT_NAME = os.getenv("TARGET_AGENT_NAME", "target-agent")
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "30"))
STALE_AFTER_MISSES = int(os.getenv("STALE_AFTER_MISSES", "2"))

AGENT_LINE_RE = re.compile(
    r"ID:\s*(?P<id>\d+),\s*Name:\s*(?P<name>[^,]+),\s*IP:\s*(?P<ip>[^,]+),\s*(?P<status>.+)$"
)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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
    created = _docker_request(
        "POST",
        f"/containers/{container}/exec",
        {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True, "Tty": True},
    )
    exec_id = created["Id"]

    conn = _UnixHTTPConnection("localhost")
    conn.request(
        "POST",
        f"/exec/{exec_id}/start",
        body=json.dumps({"Detach": False, "Tty": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    output = resp.read().decode(errors="replace")
    conn.close()

    info = _docker_request("GET", f"/exec/{exec_id}/json")
    return info.get("ExitCode", -1), output


def docker_restart(container: str) -> None:
    _docker_request("POST", f"/containers/{container}/restart?t=10")


def container_running(container: str) -> bool:
    try:
        info = _docker_request("GET", f"/containers/{container}/json")
    except Exception:
        return False
    return bool(info.get("State", {}).get("Running"))


def list_agents() -> list[dict[str, str]]:
    code, output = docker_exec(WAZUH_CONTAINER, ["/var/ossec/bin/agent_control", "-l"])
    if code != 0:
        raise RuntimeError(f"agent_control failed with exit {code}: {output.strip()}")

    agents: list[dict[str, str]] = []
    for line in output.splitlines():
        match = AGENT_LINE_RE.search(line.strip())
        if match:
            agents.append(match.groupdict())
    return agents


def remove_agent(agent_id: str) -> None:
    code, output = docker_exec(
        WAZUH_CONTAINER,
        ["sh", "-lc", f"printf 'y\\n' | /var/ossec/bin/manage_agents -r {agent_id}"],
    )
    if code != 0:
        raise RuntimeError(f"failed to remove Wazuh agent {agent_id}: {output.strip()}")


def repair_stale_target_agents(agents: list[dict[str, str]]) -> bool:
    matching = [agent for agent in agents if agent["name"].strip() == TARGET_AGENT_NAME]
    if not matching:
        print(f"[watchdog] no Wazuh record for {TARGET_AGENT_NAME}; restarting target to enroll", flush=True)
        docker_restart(TARGET_CONTAINER)
        return True

    active = [agent for agent in matching if "Active" in agent["status"]]
    stale = [agent for agent in matching if "Active" not in agent["status"]]

    if active and not stale:
        return False

    # If one record is active, clean only the disconnected duplicates. If none
    # is active, remove all records so the target can enroll with a fresh key.
    to_remove = stale if active else matching
    print(
        f"[watchdog] repairing {TARGET_AGENT_NAME}: "
        f"active={len(active)} stale={len(stale)} remove={[a['id'] for a in to_remove]}",
        flush=True,
    )
    for agent in to_remove:
        remove_agent(agent["id"])

    if container_running(TARGET_CONTAINER):
        docker_restart(TARGET_CONTAINER)
    return True


def main() -> None:
    if not os.path.exists(DOCKER_SOCKET):
        raise SystemExit(f"Docker socket not found at {DOCKER_SOCKET}")

    print(
        f"[watchdog] monitoring Wazuh agent {TARGET_AGENT_NAME} "
        f"every {CHECK_INTERVAL_SECONDS}s",
        flush=True,
    )
    misses = 0
    while True:
        try:
            if not container_running(WAZUH_CONTAINER):
                print(f"[watchdog] {WAZUH_CONTAINER} is not running", flush=True)
                misses = 0
            else:
                agents = list_agents()
                target_agents = [agent for agent in agents if agent["name"].strip() == TARGET_AGENT_NAME]
                has_active = any("Active" in agent["status"] for agent in target_agents)
                has_stale = any("Active" not in agent["status"] for agent in target_agents)

                if has_active and not has_stale:
                    misses = 0
                else:
                    misses += 1
                    print(
                        f"[watchdog] {TARGET_AGENT_NAME} unhealthy "
                        f"(miss {misses}/{STALE_AFTER_MISSES})",
                        flush=True,
                    )
                    if misses >= STALE_AFTER_MISSES:
                        if repair_stale_target_agents(agents):
                            misses = 0
        except Exception as exc:
            print(f"[watchdog] check failed: {exc}", flush=True)

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
