"""
routes/system.py – System utility endpoints.

[VULN APP-02] COMMAND INJECTION
The `host` parameter is passed directly to os.popen() with no sanitization.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.system")
system_bp = Blueprint("system", __name__)

_PING_PAGE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Network Diagnostics — AcmeCorp IT</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;}

.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;gap:12px;}
.topbar .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#eab308,#f59e0b);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:14px;}
.topbar span{font-size:15px;font-weight:600;color:#e2e8f0;}
.topbar .badge{margin-left:12px;font-size:10px;background:rgba(234,179,8,.15);border:1px solid rgba(234,179,8,.3);color:#facc15;padding:3px 10px;border-radius:20px;letter-spacing:.06em;}

.container{max-width:720px;margin:0 auto;padding:40px 24px;}

.warn-banner{background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:10px;padding:14px 18px;margin-bottom:28px;display:flex;align-items:center;gap:10px;font-size:12px;color:#fbbf24;}
.warn-banner .icon{font-size:18px;}

h2{font-size:20px;font-weight:600;color:#e2e8f0;margin-bottom:6px;}
.sub{font-size:13px;color:#64748b;margin-bottom:24px;}

.tool-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:24px;margin-bottom:20px;}
.tool-card h3{font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:12px;display:flex;align-items:center;gap:8px;}
.tool-card h3 .dot{width:8px;height:8px;border-radius:50%;background:#22c55e;}

.input-row{display:flex;gap:8px;}
.input-row input{flex:1;padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e2e8f0;font-size:14px;font-family:monospace;outline:none;}
.input-row input:focus{border-color:rgba(234,179,8,.5);}
.input-row button{padding:10px 20px;background:linear-gradient(135deg,#eab308,#f59e0b);border:none;border-radius:8px;color:#1a1f2e;font-size:13px;font-weight:600;cursor:pointer;}

.output{margin-top:16px;background:#0a0c12;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:16px;font-family:'Consolas','Courier New',monospace;font-size:12px;color:#a3e635;white-space:pre-wrap;max-height:320px;overflow:auto;line-height:1.6;}

.back{display:inline-block;margin-top:24px;font-size:12px;}
</style>
</head><body>

<div class="topbar">
  <div class="logo">&#9881;</div>
  <span>IT Admin Panel</span>
  <div class="badge">INTERNAL USE ONLY</div>
</div>

<div class="container">
  <div class="warn-banner">
    <div class="icon">&#9888;</div>
    <span>This tool is restricted to authorized IT staff. All activity is logged and monitored.</span>
  </div>

  <h2>&#128225; Network Diagnostics</h2>
  <div class="sub">Test connectivity to internal and external hosts</div>

  <div class="tool-card">
    <h3><div class="dot"></div> Ping Test</h3>
    <form method="GET" action="{{ lab_url('/system/ping') }}">
      <div class="input-row">
        <input name="host" value="{{ host }}" placeholder="Enter hostname or IP (e.g. 127.0.0.1)"/>
        <button type="submit">Run Ping</button>
      </div>
    </form>
    <div class="output">{{ output }}</div>
  </div>

  <a href="{{ lab_url('/') }}" class="back">&larr; Back to Portal</a>
</div>
</body></html>
"""


@system_bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    logger.info(json.dumps({
        "event": "ping_request",
        "endpoint": "/system/ping",
        "host_param": host,
        "source_ip": request.remote_addr,
    }))

    # Lab evidence — generic usage
    import evidence
    evidence.record(
        "diagnostics_used",
        module_id="cmd_injection",
        path="/system/ping", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        extra={"host_param": host},
    )
    # Detect injection patterns
    SEPARATORS = (";", "|", "&&", "||", "`", "$(")
    if any(s in host for s in SEPARATORS):
        evidence.record(
            "command_separator_observed",
            module_id="cmd_injection",
            path="/system/ping", method="GET",
            source_ip=request.remote_addr,
        via=current_app.detect_via(),
            severity="medium",
            extra={"host_param": host[:200]},
        )

    # [VULN] direct shell injection — host concatenated unsanitized
    output = os.popen(f"ping -c 2 {host} 2>&1").read()  # noqa: S605

    logger.info(json.dumps({
        "event": "ping_output",
        "host_param": host,
        "output_length": len(output),
    }))

    # If the output contains evidence of extra command execution, flag it
    INDICATORS = ("uid=", "root:", "/bin/", "/etc/", "drwx", "-rwx", "Linux ")
    if any(s in output for s in INDICATORS):
        evidence.record(
            "command_injection_detected",
            module_id="cmd_injection",
            path="/system/ping", method="GET",
            source_ip=request.remote_addr,
        via=current_app.detect_via(),
            severity="critical",
            extra={"host_param": host[:200], "output_excerpt": output[:300]},
        )

    return render_template_string(_PING_PAGE, host=host, output=output)
