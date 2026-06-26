"""
agent.py -- Watcher Agent main loop.

Pipeline:
  1. Resolve analyst identity + session code  (identity.py)
  2. Poll coordinator until session is active  (coordinator_client.py)
  3. Tail the audit log                        [tail thread]
     Parse EXECVE lines -> push (t_offset, cmd) onto a queue
  4. Every BATCH_INTERVAL seconds              [batch thread]
     Drain queue -> classify via Ollama -> POST to BlueTeam API
  5. On SIGINT/SIGTERM: flush remaining batch, then exit cleanly
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import signal
import sys
import threading
import time
from typing import Optional

import requests
from dotenv import load_dotenv

from identity import resolve_identity
from coordinator_client import wait_for_session

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("watcher")

# ── Config ────────────────────────────────────────────────────────────────────

ANALYST_ID      = os.getenv("ANALYST_ID")
COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://localhost:8000")
BLUETEAM_URL    = os.getenv("BLUETEAM_URL",    "http://localhost:8010")
OLLAMA_URL      = os.getenv("OLLAMA_URL",      "http://localhost:11434")
BATCH_INTERVAL  = int(os.getenv("BATCH_INTERVAL", "30"))
AUDIT_LOG       = os.getenv("AUDIT_LOG",       "/var/log/audit/audit.log")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "llama3.2")

# Timeout for a single Ollama call — 1.5x the batch interval is enough headroom
# for slow local inference without blocking the batch thread for minutes.
_OLLAMA_TIMEOUT = max(120, BATCH_INTERVAL + 15)

# ── Noise filter ──────────────────────────────────────────────────────────────

_NOISE_PATTERNS = re.compile(
    r"(auditctl|ausearch|auditd|aureport|python[0-9.]?|/proc/|/sys/|"
    r"systemd|dbus|cron|sshd|watcher\.py|agent\.py)",
    re.IGNORECASE,
)

# ── Valid event types ─────────────────────────────────────────────────────────

_VALID_EVENT_TYPES = {
    "investigation_started",
    "incident_confirmed",
    "containment_initiated",
    "containment_succeeded",
    "alert_denied",
    "evidence_preserved",
    "eradication_completed",
    "recovery_validated",
}

# ── Shared state ──────────────────────────────────────────────────────────────

# Commands flow from the tail thread to the batch thread through this queue.
_cmd_queue: queue.Queue[tuple[int, str]] = queue.Queue()

# Set by SIGINT/SIGTERM; both threads watch it to exit cleanly.
_shutdown = threading.Event()


# ── Audit log parsing ─────────────────────────────────────────────────────────

def _parse_execve_line(line: str) -> Optional[tuple[float, str]]:
    """Return (epoch, command) from an EXECVE audit line, or None."""
    if "type=EXECVE" not in line:
        return None

    ts_match = re.search(r"msg=audit\((\d+\.\d+):", line)
    if not ts_match:
        return None
    epoch = float(ts_match.group(1))

    args: list[str] = []
    for m in re.finditer(r'a\d+="([^"]*)"', line):
        args.append(m.group(1))
    if not args:
        # Hex-encoded args fallback
        for m in re.finditer(r'a\d+=([0-9A-Fa-f]+)(?:\s|$)', line):
            try:
                args.append(bytes.fromhex(m.group(1)).decode("utf-8", errors="replace"))
            except ValueError:
                pass

    command = " ".join(args).strip()
    return (epoch, command) if command else None


# ── Tail thread ───────────────────────────────────────────────────────────────

def _tail_thread(path: str, session_start: float) -> None:
    """Read new EXECVE lines from *path* and push filtered commands onto _cmd_queue.

    Runs until _shutdown is set.  Handles log rotation by inode comparison.
    The tail loop sleeps 200 ms when the log is idle — CPU is negligible and
    the batch thread's timer runs independently, so no heartbeat yield is needed.
    """
    try:
        fh = open(path, "r", errors="replace")
        fh.seek(0, 2)           # start from the current end, not the beginning
    except OSError as exc:
        logger.error("[tail] cannot open %s: %s", path, exc)
        _shutdown.set()         # unblock the batch thread so main() can exit
        return

    current_inode = os.fstat(fh.fileno()).st_ino
    logger.info("[tail] watching %s", path)

    while not _shutdown.is_set():
        line = fh.readline()
        if line:
            result = _parse_execve_line(line)
            if result:
                epoch, command = result
                if not _NOISE_PATTERNS.search(command):
                    t_offset = max(0, int(epoch - session_start))
                    _cmd_queue.put((t_offset, command))
                    logger.debug("[tail] queued t+%ds: %s", t_offset, command)
        else:
            time.sleep(0.2)
            # Detect log rotation
            try:
                new_inode = os.stat(path).st_ino
                if new_inode != current_inode:
                    fh.close()
                    fh = open(path, "r", errors="replace")
                    current_inode = new_inode
                    logger.info("[tail] log rotated -- reopened %s", path)
            except OSError:
                pass

    fh.close()
    logger.info("[tail] stopped")


# ── Ollama classification ─────────────────────────────────────────────────────

def _classify_with_ollama(
    analyst_id: str,
    commands: list[tuple[int, str]],
) -> list[dict]:
    """Send a batch of (t_offset_sec, command) pairs to Ollama for classification."""
    if not commands:
        return []

    numbered = "\n".join(
        f"{i+1}. [t=+{t}s] {cmd}"
        for i, (t, cmd) in enumerate(commands)
    )

    prompt = (
        f"Analyst: {analyst_id}\n"
        f"Commands observed:\n{numbered}\n\n"
        "You are a SOC event classifier. For each command, decide which SOC action it represents.\n"
        "Return ONLY a JSON object — no explanation, no markdown.\n\n"
        "CLASSIFICATION RULES (match the command, not the file name):\n"
        "  investigation_started  = analyst READ a file or searched logs: cat, less, more, head, tail, grep, find, ls, strings, file, stat, lsof, ps, netstat, ss\n"
        "  evidence_preserved     = analyst COPIED or HASHED an artifact: cp, mv, tar, zip, sha256sum, md5sum, sha1sum, tcpdump -w, dd\n"
        "  containment_initiated  = analyst BLOCKED or KILLED something: iptables, ufw, firewall-cmd, kill, pkill, ifconfig down, ip link set down, service stop\n"
        "  containment_succeeded  = analyst VERIFIED a block is active: iptables -L, ufw status, netstat check after block\n"
        "  incident_confirmed     = analyst explicitly confirmed attack is real\n"
        "  alert_denied           = analyst dismissed alert as false positive\n"
        "  eradication_completed  = analyst REMOVED threat: rm, shred, userdel, apt remove, systemctl disable\n"
        "  recovery_validated     = analyst confirmed service is back: curl health check, ping, systemctl status, wget\n\n"
        "EXAMPLES:\n"
        "  cat /var/log/auth.log              -> investigation_started\n"
        "  less /var/log/nginx/access.log     -> investigation_started\n"
        "  grep 'Failed' /var/log/auth.log    -> investigation_started\n"
        "  tail -f /var/log/syslog            -> investigation_started\n"
        "  sha256sum /var/log/auth.log        -> evidence_preserved\n"
        "  cp /var/log/auth.log /tmp/evidence -> evidence_preserved\n"
        "  tar czf /tmp/ev.tar.gz /var/log    -> evidence_preserved\n"
        "  iptables -A INPUT -s 1.2.3.4 -j DROP -> containment_initiated\n"
        "  kill -9 1234                       -> containment_initiated\n"
        "  rm /tmp/malware.sh                 -> eradication_completed\n"
        "  curl http://service/health         -> recovery_validated\n\n"
        "Classify EVERY command. Return one event per command in order.\n"
        "Skip only commands that are clearly noise (auditd internals, cron, systemd).\n"
        'Output format: {"events": [{"event_type": "<type>", "t_offset_sec": <int>, "detail": "<one sentence>"}]}'
    )

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=_OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        raw_text = resp.json().get("response", "")
    except requests.RequestException as exc:
        logger.error("[ollama] request failed: %s", exc)
        return []

    json_match = re.search(r'\{.*"events"\s*:.*\}', raw_text, re.DOTALL)
    if not json_match:
        logger.warning("[ollama] no JSON in response: %s", raw_text[:200])
        return []

    try:
        parsed = json.loads(json_match.group(0))
    except json.JSONDecodeError as exc:
        logger.warning("[ollama] JSON parse error: %s -- raw: %s", exc, raw_text[:200])
        return []

    events = parsed.get("events", [])
    if not isinstance(events, list):
        return []

    validated = []
    for ev in events:
        et = ev.get("event_type", "")
        if et in _VALID_EVENT_TYPES and isinstance(ev.get("t_offset_sec"), (int, float)):
            validated.append({
                "event_type":   et,
                "t_offset_sec": int(ev["t_offset_sec"]),
                "detail":       str(ev.get("detail", ""))[:300],
            })
    return validated


# ── BlueTeam poster ───────────────────────────────────────────────────────────

def _post_action(
    analyst_id: str,
    incident_id: str,
    scenario_id: str,
    event_type: str,
    t_offset_sec: int,
    detail: str,
    timestamp: float,
) -> None:
    payload = {
        "analyst_id":   analyst_id,
        "incident_id":  incident_id,
        "scenario_id":  scenario_id,
        "event_type":   event_type,
        "t_offset_sec": t_offset_sec,
        "detail":       detail,
        "timestamp":    timestamp,
    }
    try:
        resp = requests.post(
            f"{BLUETEAM_URL}/blueteam/analyst-action",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("[blueteam] posted event_type=%s  t_offset=%ds", event_type, t_offset_sec)
    except requests.RequestException as exc:
        logger.error("[blueteam] post failed: %s", exc)


# ── Batch thread ──────────────────────────────────────────────────────────────

def _flush(analyst_id: str, incident_id: str, scenario_id: str, session_start: float) -> None:
    """Drain _cmd_queue, classify with Ollama, post each event."""
    batch: list[tuple[int, str]] = []
    while True:
        try:
            batch.append(_cmd_queue.get_nowait())
        except queue.Empty:
            break

    if not batch:
        return

    logger.info("[batch] classifying %d command(s) with Ollama", len(batch))
    events = _classify_with_ollama(analyst_id, batch)

    for ev in events:
        detail = ev["detail"].strip() or (f"Analyst ran: {batch[-1][1]}" if batch else "Action recorded")
        _post_action(
            analyst_id=analyst_id,
            incident_id=incident_id,
            scenario_id=scenario_id,
            event_type=ev["event_type"],
            t_offset_sec=ev["t_offset_sec"],
            detail=detail,
            timestamp=session_start + ev["t_offset_sec"],
        )


def _batch_thread(
    analyst_id: str,
    incident_id: str,
    scenario_id: str,
    session_start: float,
) -> None:
    """Flush _cmd_queue every BATCH_INTERVAL seconds, then once more on shutdown.

    Uses _shutdown.wait(timeout) instead of time.sleep so the batch fires
    exactly at BATCH_INTERVAL whether the audit log is busy or completely quiet.
    """
    logger.info("[batch] started -- interval=%ds", BATCH_INTERVAL)

    while not _shutdown.wait(timeout=BATCH_INTERVAL):
        _flush(analyst_id, incident_id, scenario_id, session_start)

    # Final flush: catch any commands queued between the last batch and shutdown
    _flush(analyst_id, incident_id, scenario_id, session_start)
    logger.info("[batch] stopped")


# ── Signal handler ────────────────────────────────────────────────────────────

def _on_signal(sig, frame) -> None:
    logger.info("Signal %s -- shutting down gracefully...", sig)
    _shutdown.set()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    analyst_id, session_code = resolve_identity()
    incident_id, scenario_id, session_start = wait_for_session(COORDINATOR_URL, session_code)

    print(f"\nWatcher active -- monitoring {AUDIT_LOG}")
    print(f"Batching every {BATCH_INTERVAL}s  ->  {BLUETEAM_URL}/blueteam/analyst-action\n")

    # Tail thread: daemon so it auto-exits if main() returns unexpectedly
    t_tail = threading.Thread(
        target=_tail_thread,
        args=(AUDIT_LOG, session_start),
        daemon=True,
        name="watcher-tail",
    )
    # Batch thread: non-daemon so main() waits for the final flush to complete
    t_batch = threading.Thread(
        target=_batch_thread,
        args=(analyst_id, incident_id, scenario_id, session_start),
        daemon=False,
        name="watcher-batch",
    )

    t_tail.start()
    t_batch.start()
    t_batch.join()      # blocks until _shutdown is set and final flush completes

    logger.info("Watcher exited cleanly.")


if __name__ == "__main__":
    main()
