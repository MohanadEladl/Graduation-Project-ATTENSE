"""
routes_op/system.py — Operator-mode command injection with REAL difficulty levels.

?level=easy|medium|hard selects how aggressively the host parameter is filtered,
so each difficulty needs a DIFFERENT injection technique and emits a DIFFERENT
goal event:

  Easy   (variant "semicolon_basic") → nothing stripped.  `;` chaining works.
         Goal: cmd_injection_semicolon_success.   e.g.  127.0.0.1; id
  Medium (variant "pipe_redirect")   → `;` stripped.  `|` / `&&` still work.
         Goal: cmd_injection_pipe_success.         e.g.  127.0.0.1 | id
  Hard   (variant "subshell")        → `;` `|` `&&` `||` stripped.  Only `$()`
         / backtick command substitution survives.
         Goal: cmd_injection_subshell_success.     e.g.  127.0.0.1$(id)

Local lab target only: the injected command runs against THIS container, which is
the intended vulnerability. `command_separator_observed` still fires for any
attempt (evidence/quality) but is NOT a completion trigger.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.system_op")
system_op_bp = Blueprint("system_op", __name__)

from routes.system import _PING_PAGE  # noqa: E402

_INDICATORS = ("uid=", "root:", "/bin/", "/etc/", "drwx", "-rwx", "Linux ")
_SEPARATORS = (";", "|", "&&", "||", "`", "$(")


def _sanitize(host: str, level: str) -> str:
    """Level-gated filter: higher levels strip the easier separators."""
    if not host:
        return host
    if level == "medium":
        return host.replace(";", "")                       # ; blocked; | survives
    if level == "hard":
        for tok in (";", "||", "&&", "|"):                 # separators blocked; $()/`` survive
            host = host.replace(tok, "")
        return host
    return host                                            # easy: nothing blocked


@system_op_bp.route("/ping")
def ping():
    raw = request.args.get("host", "127.0.0.1")
    level = (request.args.get("level") or "easy").strip().lower()
    if level in ("semicolon_basic", "semicolon"):
        level = "easy"
    elif level in ("pipe_redirect", "pipe"):
        level = "medium"
    elif level in ("subshell",):
        level = "hard"

    host = _sanitize(raw, level)

    logger.info(json.dumps({
        "event": "ping_request", "endpoint": "/op/system/ping",
        "level": level, "host_param": raw, "sanitized": host,
        "source_ip": request.remote_addr,
    }))

    import evidence
    via = current_app.detect_via()
    evidence.record(
        "diagnostics_used", module_id="cmd_injection", path="/op/system/ping",
        method="GET", source_ip=request.remote_addr, via=via,
        extra={"host_param": raw, "level": level, "backend": "operator"},
    )
    if any(s in raw for s in _SEPARATORS):
        evidence.record(
            "command_separator_observed", module_id="cmd_injection",
            path="/op/system/ping", method="GET", source_ip=request.remote_addr,
            via=via, severity="medium",
            extra={"host_param": raw[:200], "sanitized": host[:200],
                   "level": level, "backend": "operator"},
        )

    # Hard uses a quoted host so a subshell's multi-word output reflects whole
    # (`$()` still executes inside double quotes). Easy/Medium stay unquoted so
    # `;` and `|` act as real shell operators.
    if level == "hard":
        output = os.popen(f'ping -c 2 "{host}" 2>&1').read()  # noqa: S605
    else:
        output = os.popen(f'ping -c 2 {host} 2>&1').read()    # noqa: S605

    if any(ind in output for ind in _INDICATORS):
        # Attribute the success to the technique whose metacharacter SURVIVED
        # this level's filter — that's the difficulty-specific goal event.
        event = None
        if level == "hard" and ("$(" in host or "`" in host):
            event = "cmd_injection_subshell_success"
        elif level == "medium" and any(t in host for t in ("|", "&&", "||")):
            event = "cmd_injection_pipe_success"
        elif level == "easy" and ";" in host:
            event = "cmd_injection_semicolon_success"
        if event:
            evidence.record(
                event, module_id="cmd_injection", path="/op/system/ping",
                method="GET", source_ip=request.remote_addr, via=via,
                severity="critical",
                extra={"host_param": raw[:200], "output_excerpt": output[:300],
                       "level": level, "backend": "operator"},
            )

    return render_template_string(_PING_PAGE, host=host, output=output)
