"""
routes_op/system.py — Operator-mode HARDER command injection.

The host parameter is filtered: `;` and `|` are stripped before being
passed to popen. Backticks (`...`) and `$(...)` STILL pass through — the
bypass is to use those instead of the obvious separators.

Same evidence event types so lab_progress.py is unchanged.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.system_op")
system_op_bp = Blueprint("system_op", __name__)

from routes.system import _PING_PAGE  # noqa: E402


def _sanitize_host(host: str) -> str:
    """Strip the obvious separators. Backticks and $() survive."""
    if not host:
        return host
    return host.replace(";", "").replace("|", "").replace("&&", "").replace("||", "")


@system_op_bp.route("/ping")
def ping():
    raw  = request.args.get("host", "127.0.0.1")
    host = _sanitize_host(raw)

    logger.info(json.dumps({
        "event":     "ping_request",
        "endpoint":  "/op/system/ping",
        "host_param": raw,
        "sanitized":  host,
        "source_ip":  request.remote_addr,
    }))

    import evidence
    via = current_app.detect_via()
    evidence.record(
        "diagnostics_used",
        module_id="cmd_injection",
        path="/op/system/ping", method="GET",
        source_ip=request.remote_addr,
        via=via,
        extra={"host_param": raw, "backend": "operator"},
    )

    # We credit `command_separator_observed` whenever the RAW input contains
    # any separator-like char — including the ones we filtered. Learners get
    # credit for trying ; and | even though they don't work.
    SEPARATORS = (";", "|", "&&", "||", "`", "$(")
    if any(s in raw for s in SEPARATORS):
        evidence.record(
            "command_separator_observed",
            module_id="cmd_injection",
            path="/op/system/ping", method="GET",
            source_ip=request.remote_addr,
            via=via,
            severity="medium",
            extra={"host_param": raw[:200], "sanitized": host[:200], "backend": "operator"},
        )

    output = os.popen(f"ping -c 2 {host} 2>&1").read()  # noqa: S605

    INDICATORS = ("uid=", "root:", "/bin/", "/etc/", "drwx", "-rwx", "Linux ")
    if any(s in output for s in INDICATORS):
        evidence.record(
            "command_injection_detected",
            module_id="cmd_injection",
            path="/op/system/ping", method="GET",
            source_ip=request.remote_addr,
            via=via,
            severity="critical",
            extra={"host_param": raw[:200], "output_excerpt": output[:300],
                   "backend": "operator"},
        )

    return render_template_string(_PING_PAGE, host=host, output=output)
