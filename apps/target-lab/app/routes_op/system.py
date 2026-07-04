"""
routes_op/system.py - Operator-mode HARDER command injection.

The host parameter is filtered: `;`, `|`, `&&`, and `||` are all stripped
before being passed to popen. Backticks (`...`) and `$(...)` STILL pass
through - the bypass is to use those instead of the obvious separators.

Same evidence event types so lab_progress.py is unchanged.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.system_op")
system_op_bp = Blueprint("system_op", __name__)

from routes.system import _PING_PAGE # noqa: E402
from route_security import has_command_output_indicator, has_shell_separator # noqa: E402


def _sanitize_host(host: str) -> str:
    """Strip the obvious separators. Backticks and $() survive."""
    if not host:
        return host
    return host.replace(";", "").replace("|", "").replace("&&", "").replace("||", "")


@system_op_bp.route("/ping")
def ping():
    raw = request.args.get("host", "127.0.0.1")
    host = _sanitize_host(raw)

    logger.info(json.dumps({
        "event": "ping_request",
        "endpoint": "/op/system/ping",
        "host_param": raw,
        "sanitized": host,
        "source_ip": current_app.fake_attacker_ip(),
    }))

    import evidence
    via = current_app.detect_via()
    session_id = current_app.current_session_id()
    evidence.record(
        "diagnostics_used",
        module_id="cmd_injection",
        path="/op/system/ping", method="GET",
        source_ip=current_app.fake_attacker_ip(),
        via=via,
        session_id=session_id,
        extra={"host_param": raw, "backend": "operator"},
    )

    # We credit `command_separator_observed` whenever the RAW input contains
    # any separator-like char - including the ones we filtered. Learners get
    # credit for trying ; and | even though they don't work.
    if has_shell_separator(raw):
        evidence.record(
            "command_separator_observed",
            module_id="cmd_injection",
            path="/op/system/ping", method="GET",
            source_ip=current_app.fake_attacker_ip(),
            via=via,
            session_id=session_id,
            severity="medium",
            extra={"host_param": raw[:200], "sanitized": host[:200], "backend": "operator"},
        )

    output = os.popen(f"ping -c 2 {host} 2>&1").read() # noqa: S605
    if has_command_output_indicator(output):
        evidence.record(
            "command_injection_detected",
            module_id="cmd_injection",
            path="/op/system/ping", method="GET",
            source_ip=current_app.fake_attacker_ip(),
            via=via,
            session_id=session_id,
            severity="critical",
            extra={"host_param": raw[:200], "output_excerpt": output[:300],
                   "backend": "operator"},
        )

    return render_template_string(_PING_PAGE, host=host, output=output)
