"""
backend/chain_engine.py — Attack chain session management.

An "attack chain" is a multi-step mission where each module must be completed
(score >= threshold) before the next step unlocks.
"""
from __future__ import annotations

import logging as _logging
import os
import time
import uuid
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

_log = _logging.getLogger(__name__)

TARGET_AGENT_URL = os.getenv("LAB_EVENTS_URL", "http://target-agent")

# ── Chain definitions ───────────────────────────────────────────────────────

CHAINS: Dict[str, Dict[str, Any]] = {
    "full_compromise": {
        "name": "Full Compromise",
        "description": "Perform a complete network compromise: recon, authentication bypass, XSS, then CSRF.",
        "steps": [
            {"module_id": "recon",       "label": "Recon",            "threshold": 60},
            {"module_id": "brute_force", "label": "Auth Bypass",      "threshold": 60},
            {"module_id": "xss",         "label": "XSS",              "threshold": 60},
            {"module_id": "csrf",        "label": "CSRF",             "threshold": 60},
        ],
    },
    "root_the_box": {
        "name": "Root the Box",
        "description": "Escalate privileges from guest to root via command injection and file upload.",
        "steps": [
            {"module_id": "recon",         "label": "Recon",          "threshold": 60},
            {"module_id": "cmd_injection", "label": "Cmd Injection",  "threshold": 60},
            {"module_id": "dir_traversal", "label": "Dir Traversal",  "threshold": 60},
            {"module_id": "file_upload",   "label": "File Upload",    "threshold": 60},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": "Exfiltrate sensitive data: recon the target, bypass auth, traverse directories, then forge cross-site requests.",
        "steps": [
            {"module_id": "recon",         "label": "Recon",          "threshold": 60},
            {"module_id": "brute_force",   "label": "Auth Bypass",    "threshold": 60},
            {"module_id": "dir_traversal", "label": "Dir Traversal",  "threshold": 60},
            {"module_id": "csrf",          "label": "CSRF",           "threshold": 60},
        ],
    },
}

# ── In-memory chain session store ───────────────────────────────────────────

_CHAIN_SESSIONS: Dict[str, Dict[str, Any]] = {}


# ── Public API ───────────────────────────────────────────────────────────────

def list_chains() -> List[Dict[str, Any]]:
    """Return list of chain summaries (id, name, description, step_count)."""
    result = []
    for chain_id, chain in CHAINS.items():
        result.append({
            "id":          chain_id,
            "name":        chain["name"],
            "description": chain["description"],
            "step_count":  len(chain["steps"]),
        })
    return result


def get_chain(chain_id: str) -> Dict[str, Any]:
    """Return full chain definition. Raises KeyError if not found."""
    if chain_id not in CHAINS:
        raise KeyError("Chain not found: " + chain_id)
    chain = CHAINS[chain_id]
    return {
        "id":          chain_id,
        "name":        chain["name"],
        "description": chain["description"],
        "steps":       chain["steps"],
    }


def start_chain(chain_id: str, session_id: str) -> Dict[str, Any]:
    """
    Create a new chain session. Stores in _CHAIN_SESSIONS dict.
    Returns the chain session record.
    Raises KeyError if chain_id not found.
    """
    if chain_id not in CHAINS:
        raise KeyError("Chain not found: " + chain_id)

    chain_session_id = str(uuid.uuid4())
    record: Dict[str, Any] = {
        "id":                 chain_session_id,
        "chain_id":           chain_id,
        "session_id":         session_id,
        "current_step_index": 0,
        "started_at":         time.time(),
        "completed_at":       None,
        # Persisted per-phase results — keyed by phase index.
        # Populated by advance_chain() before evidence is reset so the
        # final report always shows accurate per-phase scores.
        "phase_results":      {},
    }
    _CHAIN_SESSIONS[chain_session_id] = record
    return dict(record)


def get_chain_session(chain_session_id: str) -> Dict[str, Any]:
    """Return chain session. Raises KeyError if not found."""
    if chain_session_id not in _CHAIN_SESSIONS:
        raise KeyError("Chain session not found: " + chain_session_id)
    return dict(_CHAIN_SESSIONS[chain_session_id])


def check_step_complete(chain_session_id: str) -> bool:
    """
    Check if the CURRENT step of the chain session is complete.

    Calls lab_progress.compute() with:
      - module_id = current step's module_id
      - variant_id = None  (chains always use default variant)
      - mission_started_at = chain session's started_at timestamp

    Returns True if score >= step's threshold.
    """
    if chain_session_id not in _CHAIN_SESSIONS:
        raise KeyError("Chain session not found: " + chain_session_id)

    session = _CHAIN_SESSIONS[chain_session_id]
    chain = CHAINS[session["chain_id"]]
    steps = chain["steps"]
    idx = session["current_step_index"]

    if idx >= len(steps):
        # All steps already completed
        return True

    step = steps[idx]
    module_id = step["module_id"]
    threshold = step["threshold"]

    from backend import lab_progress
    result = lab_progress.compute(
        module_id=module_id,
        mission_started_at=session["started_at"],
        variant_id=None,
    )
    score = int(result.get("progress_percent", 0))
    return score >= threshold


def advance_chain(chain_session_id: str) -> Dict[str, Any]:
    """
    Advance to the next step.

    - Calls POST {TARGET_AGENT_URL}/lab/events/reset to clear evidence
    - Increments current_step_index
    - If all steps complete, sets completed_at = time.time()
    - Returns updated chain session

    Raises KeyError if not found.
    Raises ValueError if current step not complete.
    """
    if chain_session_id not in _CHAIN_SESSIONS:
        raise KeyError("Chain session not found: " + chain_session_id)

    session = _CHAIN_SESSIONS[chain_session_id]
    if session["completed_at"] is not None:
        return dict(session)

    if not check_step_complete(chain_session_id):
        session = _CHAIN_SESSIONS[chain_session_id]
        chain = CHAINS[session["chain_id"]]
        idx = session["current_step_index"]
        step = chain["steps"][idx]
        raise ValueError(
            "Current step '" + step["label"] + "' is not yet complete. "
            "Score must reach " + str(step["threshold"]) + "%."
        )

    # Snapshot current phase result BEFORE wiping evidence
    from backend import lab_progress as _lp
    chain = CHAINS[session["chain_id"]]
    steps = chain["steps"]
    idx = session["current_step_index"]
    step = steps[idx]
    _result = _lp.compute(
        module_id=step["module_id"],
        mission_started_at=session["started_at"],
        variant_id=None,
    )
    _score = int(_result.get("progress_percent", 0))
    session["phase_results"][idx] = {
        "phase_index":       idx,
        "module_id":         step["module_id"],
        "label":             step["label"],
        "threshold":         step["threshold"],
        "score":             _score,
        "passed":            _score >= step["threshold"],
        "evidence":          _result.get("evidence", []),
        "completed_tasks":   _result.get("completed_tasks", []),
        "timestamp":         time.time(),
    }

    # Reset target-agent evidence — swallow any failure
    reset_url = TARGET_AGENT_URL + "/lab/events/reset"
    try:
        req = urllib.request.Request(
            reset_url, data=b"", method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=4):
            pass
    except Exception as _exc:
        _log.warning("chain_engine: reset failed for chain session %s: %s", chain_session_id, _exc)

    session["current_step_index"] += 1

    if session["current_step_index"] >= len(steps):
        session["completed_at"] = time.time()

    return dict(session)


def get_chain_report(chain_session_id: str) -> Dict[str, Any]:
    """
    Return summary: chain_id, chain_name, steps (with scores), total_score, grade, completed.
    For each step, call lab_progress.compute() to get the score.
    """
    if chain_session_id not in _CHAIN_SESSIONS:
        raise KeyError("Chain session not found: " + chain_session_id)

    session = _CHAIN_SESSIONS[chain_session_id]
    chain = CHAINS[session["chain_id"]]

    from backend import lab_progress

    current_idx = session["current_step_index"]
    phase_results = session.get("phase_results", {})

    steps_out = []
    total = 0
    for i, step in enumerate(chain["steps"]):
        if i in phase_results:
            # Use persisted snapshot — evidence may have been reset already
            stored = phase_results[i]
            score = stored["score"]
            steps_out.append({
                "module_id":       step["module_id"],
                "label":           step["label"],
                "threshold":       step["threshold"],
                "score":           score,
                "passed":          stored["passed"],
                "evidence":        stored.get("evidence", []),
                "completed_tasks": stored.get("completed_tasks", []),
            })
        elif i == current_idx:
            # Live query for the active phase
            result = lab_progress.compute(
                module_id=step["module_id"],
                mission_started_at=session["started_at"],
                variant_id=None,
            )
            score = int(result.get("progress_percent", 0))
            steps_out.append({
                "module_id":       step["module_id"],
                "label":           step["label"],
                "threshold":       step["threshold"],
                "score":           score,
                "passed":          score >= step["threshold"],
                "evidence":        result.get("evidence", []),
                "completed_tasks": result.get("completed_tasks", []),
            })
        else:
            # Future phase not yet reached
            score = 0
            steps_out.append({
                "module_id":       step["module_id"],
                "label":           step["label"],
                "threshold":       step["threshold"],
                "score":           0,
                "passed":          False,
                "evidence":        [],
                "completed_tasks": [],
            })
        total += score

    num_steps = max(len(chain["steps"]), 1)
    avg_score = int(round(total / num_steps))

    if avg_score >= 90:
        grade = "A"
    elif avg_score >= 75:
        grade = "B"
    elif avg_score >= 60:
        grade = "C"
    elif avg_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "chain_session_id": chain_session_id,
        "chain_id":         session["chain_id"],
        "chain_name":       chain["name"],
        "steps":            steps_out,
        "total_score":      total,
        "avg_score":        avg_score,
        "grade":            grade,
        "completed":        session["completed_at"] is not None,
        "started_at":       session["started_at"],
        "completed_at":     session["completed_at"],
    }
