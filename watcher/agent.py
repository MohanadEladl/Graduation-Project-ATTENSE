"""
agent.py — Watcher Agent main loop.

Pipeline:
  1. Resolve analyst identity + session code (identity.py)
  2. Poll coordinator until session is active (coordinator_client.py)
  3. Tail /var/log/audit/audit.log from the current end
  4. Parse EXECVE lines → extract command + timestamp offset
  5. Batch commands every BATCH_INTERVAL seconds
  6. Send batch to Ollama → classify SOC actions
  7. POST each valid classified event to BlueTeam API
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import deque
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

# ── Config from environment ───────────────────────────────────────────────────

ANALYST_ID      = os.getenv("ANALYST_ID")          # overridden by identity.py at runtime
COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://localhost:8000")
BLUETEAM_URL    = os.getenv("BLUETEAM_URL",    "http://localhost:8010")
OLLAMA_URL      = os.getenv("OLLAMA_URL",      "http://localhost:11434")
BATCH_INTERVAL  = int(os.getenv("BATCH_INTERVAL", "30"))
AUDIT_LOG       = os.getenv("AUDIT_LOG",       "/var/log/audit/audit.log")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "llama3.2")

# ── Noise filter: skip commands from these programs / paths ───────────────────
_NOISE_PATTERNS = re.compile(
    r"(auditctl|ausearch|auditd|aureport|python[0-9.]?|/proc/|/sys/|"
    r"systemd|dbus|cron|sshd|watcher\.py|agent\.py)",
    re.IGNORECASE,
)

# ── Valid event types accepted from the LLM ──────────────────────────────────
_VALID_EVENT_TYPES = {
    "investigation_started",
    "incident_confirmed",
    "containment_initiated",
    "containment_succeeded",
    "alert_denied",
}


# ── Audit log parsing ─────────────────────────────────────────────────────────

def _parse_execve_line(line: str) -> Optional[tuple[float, str]]:
    """
    Extract (epoch_timestamp, command_string) from an EXECVE audit line.
    Returns None if the line is not a parseable EXECVE record.
    """
    if "type=EXECVE" not in line:
        return None

    # Timestamp: msg=audit(1717001234.567:123)
    ts_match = re.search(r"msg=audit\((\d+\.\d+):", line)
    if not ts_match:
        return None
    epoch = float(ts_match.group(1))

    # Collect a0, a1, a2 … argument fields
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
    if not command:
        return None

    return epoch, command


def _tail_audit_log(path: str):
    """
    Generator: open *path*, seek to end, yield new lines as they arrive.
    Reopens the file if it is rotated (inode changes).
    """
    try:
        fh = open(path, "r", errors="replace")
        fh.seek(0, 2)  # seek to end
    except OSError as exc:
        logger.error("Cannot open audit log %s: %s", path, exc)
        return

    current_inode = os.fstat(fh.fileno()).st_ino

    while True:
        line = fh.readline()
        if line:
            yield line
        else:
            time.sleep(0.2)
            # Detect log rotation
            try:
                new_inode = os.stat(path).st_ino
                if new_inode != current_inode:
                    fh.close()
                    fh = open(path, "r", errors="replace")
                    current_inode = new_inode
            except OSError:
                pass


# ── Ollama interaction ────────────────────────────────────────────────────────

def _classify_with_ollama(
    analyst_id: str,
    commands: list[tuple[int, str]],
) -> list[dict]:
    """
    Send a batch of (t_offset_sec, command) pairs to Ollama.
    Returns a list of validated event dicts (may be empty).
    """
    if not commands:
        return []

    numbered = "\n".join(
        f"{i+1}. [t=+{t}s] {cmd}"
        for i, (t, cmd) in enumerate(commands)
    )

    prompt = (
        f"Analyst: {analyst_id}\n"
        f"Commands with timestamps:\n{numbered}\n\n"
        "Classify any significant SOC response actions. Return only JSON:\n"
        '{"events": [{"event_type": "<type>", "t_offset_sec": <int>, "detail": "<one sentence>"}]}\n'
        "Valid types: investigation_started, incident_confirmed, containment_initiated, "
        "containment_succeeded, alert_denied\n"
        'If no SOC action: {"events": []}'
    )

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        raw_text = resp.json().get("response", "")
    except requests.RequestException as exc:
        logger.error("[ollama] request failed: %s", exc)
        return []

    # Extract JSON from the response (LLM may wrap it in prose)
    json_match = re.search(r'\{.*"events"\s*:.*\}', raw_text, re.DOTALL)
    if not json_match:
        logger.warning("[ollama] no JSON found in response: %s", raw_text[:200])
        return []

    try:
        parsed = json.loads(json_match.group(0))
    except json.JSONDecodeError as exc:
        logger.warning("[ollama] JSON parse error: %s — raw: %s", exc, raw_text[:200])
        return []

    events = parsed.get("events", [])
    if not isinstance(events, list):
        return []

    # Filter to only valid event_types — reject anything the LLM hallucinated
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


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. Identity
    analyst_id, session_code = resolve_identity()

    # 2. Wait for coordinator session
    incident_id, scenario_id, session_start = wait_for_session(COORDINATOR_URL, session_code)

    print(f"\nWatcher active — monitoring {AUDIT_LOG}")
    print(f"Batching every {BATCH_INTERVAL}s  →  {BLUETEAM_URL}/blueteam/analyst-action\n")

    # 3. Tail audit log
    pending: list[tuple[int, str]] = []   # (t_offset_sec, command)
    last_flush = time.time()

    for line in _tail_audit_log(AUDIT_LOG):
        result = _parse_execve_line(line)
        if result is None:
            pass
        else:
            epoch, command = result

            # Skip noise
            if _NOISE_PATTERNS.search(command):
                continue

            t_offset = max(0, int(epoch - session_start))
            pending.append((t_offset, command))

        # 4. Flush batch every BATCH_INTERVAL seconds
        if time.time() - last_flush >= BATCH_INTERVAL:
            batch = list(pending)
            pending.clear()
            last_flush = time.time()

            if batch:
                logger.info("[watcher] classifying %d command(s) with Ollama", len(batch))
                events = _classify_with_ollama(analyst_id, batch)

                for ev in events:
                    detail = ev["detail"].strip()
                    if not detail:
                        detail = f"Analyst ran: {batch[-1][1]}" if batch else "Action recorded"

                    _post_action(
                        analyst_id   = analyst_id,
                        incident_id  = incident_id,
                        scenario_id  = scenario_id,
                        event_type   = ev["event_type"],
                        t_offset_sec = ev["t_offset_sec"],
                        detail       = detail,
                        timestamp    = session_start + ev["t_offset_sec"],
                    )


if __name__ == "__main__":
    main()
