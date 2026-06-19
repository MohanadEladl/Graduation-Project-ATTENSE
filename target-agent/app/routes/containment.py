"""Authenticated API used by Cortex responders to enforce containment."""

import hmac
import logging
import os

from flask import Blueprint, jsonify, request

import containment


logger = logging.getLogger("target.containment")
containment_bp = Blueprint("containment", __name__)
SUPPORTED_ACTIONS = {
    "sanitize_input",
    "block_path",
    "remove_file",
    "enable_csrf_protection",
    "kill_process",
}


def _authorized() -> bool:
    expected = os.getenv("CONTAINMENT_API_TOKEN", "")
    supplied = request.headers.get("X-Containment-Token", "")
    return bool(expected) and hmac.compare_digest(expected, supplied)


@containment_bp.post("/actions/<action>")
def apply_action(action: str):
    if not _authorized():
        return jsonify({"success": False, "error": "unauthorized"}), 401
    if action not in SUPPORTED_ACTIONS:
        return jsonify({"success": False, "error": "unsupported action"}), 404

    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target") or "").strip()
    try:
        if action == "remove_file":
            removed = containment.remove_uploaded_file(target)
            details = {"removed": str(removed)}
        elif action == "kill_process":
            details = {"terminated": containment.kill_process(target)}
        else:
            state = containment.enable(action, target)
            details = {"state": state}
    except (ValueError, FileNotFoundError, ProcessLookupError, PermissionError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    logger.warning(
        '{"event":"containment_applied","action":"%s","target":"%s"}',
        action,
        target,
    )
    return jsonify({"success": True, "action": action, "target": target, **details})


@containment_bp.get("/state")
def get_state():
    if not _authorized():
        return jsonify({"success": False, "error": "unauthorized"}), 401
    return jsonify({"success": True, "state": containment.snapshot()})
