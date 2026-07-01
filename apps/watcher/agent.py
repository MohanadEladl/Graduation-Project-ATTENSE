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
RAW_LOG         = os.getenv("RAW_LOG", os.path.join(os.path.dirname(__file__), "raw_actions.jsonl"))

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


# ── Raw action log ───────────────────────────────────────────────────────────

def _write_raw_log(
    analyst_id: str,
    incident_id: str,
    batch: list[tuple[int, str]],
    reason: str,
) -> None:
    """Append commands that failed classification to RAW_LOG as JSONL rows.

    Every command that doesn't come out of _classify_command() as a validated
    event_type lands here -- a request failure, an unparseable response, or an
    event_type Ollama invented that isn't in _VALID_EVENT_TYPES. There is no
    silent-drop path: a command is either posted to BlueTeam, recognised as
    "none" (not a tracked SOC action -- correctly skipped), or logged here.
    """
    ts = time.time()
    try:
        with open(RAW_LOG, "a", encoding="utf-8") as f:
            for t_offset, cmd in batch:
                f.write(json.dumps({
                    "ts":           ts,
                    "analyst_id":   analyst_id,
                    "incident_id":  incident_id,
                    "t_offset_sec": t_offset,
                    "command":      cmd,
                    "reason":       reason,
                }) + "\n")
        logger.info("[raw-log] wrote %d unclassified row(s) -- reason=%s", len(batch), reason)
    except OSError as exc:
        logger.warning("[raw-log] could not write to %s: %s", RAW_LOG, exc)


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

_CLASSIFY_PROMPT_TEMPLATE = (
    "You are a SOC event classifier. Classify ONE terminal command run by a "
    "security analyst into exactly one category.\n\n"
    "Command: {command}\n\n"
    "Categories (match what the command DOES, not the file name it touches):\n"
    "  investigation_started  - reads or searches logs/system state: cat, less, more, head, tail, grep, find, ls, strings, file, stat, lsof, ps, netstat, ss\n"
    "  evidence_preserved     - copies or hashes an artifact: cp, mv, tar, zip, sha256sum, md5sum, sha1sum, tcpdump -w, dd\n"
    "  containment_initiated  - blocks or kills something: iptables, ufw, firewall-cmd, kill, pkill, ifconfig down, ip link set down, service stop\n"
    "  containment_succeeded  - verifies a block is already active: iptables -L, ufw status, netstat check after block\n"
    "  incident_confirmed     - analyst explicitly states the attack/incident is confirmed real\n"
    "  alert_denied           - analyst explicitly dismisses the alert as a false positive\n"
    "  eradication_completed  - removes the threat: rm, shred, userdel, apt remove, systemctl disable\n"
    "  recovery_validated     - confirms a service is back up: curl health check, ping, systemctl status, wget\n"
    "  none                   - the command does not match any category above\n\n"
    "Examples:\n"
    "  cat /var/log/auth.log              -> investigation_started\n"
    "  less /var/log/nginx/access.log     -> investigation_started\n"
    "  grep 'Failed' /var/log/auth.log    -> investigation_started\n"
    "  ls -la /tmp                        -> investigation_started\n"
    "  sha256sum /var/log/auth.log        -> evidence_preserved\n"
    "  cp /var/log/auth.log /tmp/evidence -> evidence_preserved\n"
    "  iptables -A INPUT -s 1.2.3.4 -j DROP -> containment_initiated\n"
    "  kill -9 1234                       -> containment_initiated\n"
    "  rm /tmp/malware.sh                 -> eradication_completed\n"
    "  curl http://service/health         -> recovery_validated\n\n"
    "Reply with ONLY this JSON object and nothing else:\n"
    '{{"event_type": "<one category from the list above>"}}'
)

# Deterministic first-token (verb) classification for well-known, unambiguous
# SOC command verbs. Built from the same command-to-category mapping the LLM
# prompt uses above. The model is unreliable even on textbook commands like
# `cat` and `sha256sum` (confirmed by direct testing -- with temperature=0 it
# consistently mislabels them without few-shot examples, and is still not
# perfectly consistent with them). Verbs in this table never touch the model:
# zero ambiguity, zero latency, 100% reproducible. Ollama is reserved for the
# long tail of commands that don't match any verb here.
_VERB_RULES: dict[str, str] = {
    # investigation_started — reads or searches logs/system state
    "cat": "investigation_started", "less": "investigation_started", "more": "investigation_started",
    "head": "investigation_started", "tail": "investigation_started", "grep": "investigation_started",
    "find": "investigation_started", "ls": "investigation_started", "strings": "investigation_started",
    "file": "investigation_started", "stat": "investigation_started", "lsof": "investigation_started",
    "ps": "investigation_started", "netstat": "investigation_started", "ss": "investigation_started",
    # evidence_preserved — copies or hashes an artifact
    "sha256sum": "evidence_preserved", "sha1sum": "evidence_preserved", "md5sum": "evidence_preserved",
    "cp": "evidence_preserved", "mv": "evidence_preserved", "tar": "evidence_preserved",
    "zip": "evidence_preserved", "dd": "evidence_preserved",
    # eradication_completed — removes the threat
    "rm": "eradication_completed", "shred": "eradication_completed", "userdel": "eradication_completed",
    # recovery_validated — confirms a service is back up
    "curl": "recovery_validated", "ping": "recovery_validated", "wget": "recovery_validated",
    # containment_initiated — blocks or kills something (no flag-dependent meaning)
    "pkill": "containment_initiated", "firewall-cmd": "containment_initiated",
}


def _classify_by_verb(command: str) -> Optional[str]:
    """Deterministically classify well-known SOC command verbs without
    consulting the model. Returns None for commands not covered here (the
    caller falls back to Ollama), or for verbs whose category genuinely
    depends on flags/sub-arguments rather than the verb alone.
    """
    parts = command.strip().split()
    if not parts:
        return None
    verb = parts[0].lower()
    rest = [p.lower() for p in parts[1:]]

    if verb == "iptables":
        return "containment_succeeded" if "-l" in rest else "containment_initiated"
    if verb == "ufw":
        return "containment_succeeded" if "status" in rest else "containment_initiated"
    if verb == "kill":
        return "containment_initiated"
    if verb == "systemctl":
        if "disable" in rest:
            return "eradication_completed"
        if "status" in rest:
            return "recovery_validated"
        if "stop" in rest:
            return "containment_initiated"
        return None
    if verb == "apt" and "remove" in rest:
        return "eradication_completed"
    if verb == "tcpdump":
        return "evidence_preserved" if "-w" in rest else None

    return _VERB_RULES.get(verb)


def _classify_command(command: str) -> Optional[str]:
    """Classify a single command, deterministically where possible and via
    Ollama otherwise.

    Returns a validated event_type, "none" if the command matches no tracked
    SOC action, or None on failure (request error, unparseable response, or
    an event_type Ollama invented that isn't in _VALID_EVENT_TYPES).

    One Ollama call per command, not one call for the whole batch: asking a
    small local model to enumerate, order, and echo back offsets for N
    commands in a single structured response is unreliable -- it drops,
    merges, and hallucinates entries under that load. Classifying one command
    in isolation is a far simpler task for the model, and we already own
    t_offset_sec and the literal command text ourselves, so the model's only
    job is picking one label -- nothing for it to fabricate.
    """
    rule_match = _classify_by_verb(command)
    if rule_match is not None:
        return rule_match

    prompt = _CLASSIFY_PROMPT_TEMPLATE.format(command=command)

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":   OLLAMA_MODEL,
                "prompt":  prompt,
                "stream":  False,
                "format":  "json",   # constrains decoding to syntactically valid JSON
                "options": {
                    "num_predict": 24,   # one short label -- no room to ramble or invent detail
                    "temperature": 0,    # deterministic classification
                },
            },
            timeout=_OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        raw_text = resp.json().get("response", "")
    except requests.RequestException as exc:
        logger.error("[ollama] request failed for command=%r: %s", command, exc)
        return None

    try:
        parsed = json.loads(raw_text)
        event_type = parsed.get("event_type", "")
    except (json.JSONDecodeError, AttributeError):
        logger.warning("[ollama] invalid JSON for command=%r: %s", command, raw_text[:200])
        return None

    if event_type == "none":
        return "none"
    if event_type in _VALID_EVENT_TYPES:
        return event_type

    logger.warning("[ollama] unrecognised event_type=%r for command=%r", event_type, command)
    return None


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
    """Drain _cmd_queue, classify each command with Ollama, post the matched ones."""
    batch: list[tuple[int, str]] = []
    while True:
        try:
            batch.append(_cmd_queue.get_nowait())
        except queue.Empty:
            break

    if not batch:
        return

    logger.info("[batch] classifying %d command(s) with Ollama", len(batch))

    failed: list[tuple[int, str]] = []
    for t_offset, cmd in batch:
        event_type = _classify_command(cmd)

        if event_type is None:
            failed.append((t_offset, cmd))
            continue
        if event_type == "none":
            continue  # not a tracked SOC action — correctly skipped, not a failure

        _post_action(
            analyst_id=analyst_id,
            incident_id=incident_id,
            scenario_id=scenario_id,
            event_type=event_type,
            t_offset_sec=t_offset,
            detail=f"Analyst ran: {cmd}",
            timestamp=session_start + t_offset,
        )

    if failed:
        _write_raw_log(analyst_id, incident_id, failed, reason="ollama_classification_failed")


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
