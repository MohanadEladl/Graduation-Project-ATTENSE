"""
main.py – Flask entry point for the intentionally vulnerable target application.

LAB PURPOSE: This app is the attack surface for the ATTENSE cyber range.
Every route is deliberately vulnerable for training and detection research.
DO NOT deploy this in any production or internet-facing environment.

Fix vs. original:
  * Uses a dedicated JSON file handler for target.* loggers instead of
    basicConfig's f-string hack. This guarantees every line in app.log
    is valid JSON, so Wazuh's json decoder will parse it cleanly.
  * Root logger still writes human-readable lines to stderr for container logs.
"""
import json
import logging
import os
from logging import LogRecord
from flask import Flask, request

from routes.home    import home_bp
from routes.auth    import auth_bp
from routes.search  import search_bp
from routes.system  import system_bp
from routes.files   import files_bp
from routes.profile import profile_bp
from routes.containment import containment_bp

# Operator-mode parallel routes (harder backend, same UI templates).
# Mounted under /op/* — reached via the lab-browser proxy at /target-op/*
# and directly from the AttackBox at http://target-agent/op/*
from routes_op.auth    import auth_op_bp
from routes_op.home    import home_op_bp
from routes_op.search  import search_op_bp
from routes_op.system  import system_op_bp
from routes_op.files   import files_op_bp
from routes_op.profile import profile_op_bp

# ── App-level JSON logger (read by Wazuh agent via ossec.conf) ────────────────
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)
APP_LOG_PATH = os.path.join(LOG_DIR, "app.log")


class JsonLineFormatter(logging.Formatter):
    """
    Produces one valid JSON object per log line.

    Each target.* logger emits a json.dumps(...) string as the message; that
    string is embedded as the JSON value of the ``message`` field so the final
    line is a well-formed JSON document that Wazuh's json decoder accepts.
    """

    def format(self, record: LogRecord) -> str:
        # Message is already a JSON object string → embed verbatim.
        msg_str = record.getMessage()
        try:
            message_obj = json.loads(msg_str)
        except (ValueError, TypeError):
            # Fallback: wrap non-JSON messages (e.g. Flask/werkzeug internals)
            message_obj = {"text": msg_str}

        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            **({"message": message_obj} if isinstance(message_obj, dict) else
               {"message": {"text": str(message_obj)}}),
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


# Root logger → stderr (container log) in plain text
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)

# Dedicated JSON handler only for our vulnerable-app loggers
_json_handler = logging.FileHandler(APP_LOG_PATH, encoding="utf-8")
_json_handler.setFormatter(JsonLineFormatter())
_json_handler.setLevel(logging.INFO)

# All target.* loggers (defined in routes/*.py) pipe here
_target_logger = logging.getLogger("target")
_target_logger.addHandler(_json_handler)
_target_logger.setLevel(logging.INFO)
# Avoid double-logging to stderr via root
_target_logger.propagate = False

app = Flask(__name__)

# ── Secret key is intentionally weak (APP-06 / session abuse) ────────────────
# [VULN] Hardcoded weak secret key — trivially guessable for session forgery.
app.secret_key = "lab-secret-123"


# ─────────────────────────────────────────────────────────────────────────────
# Prefix-aware URL helper
#
# When the lab is rendered inside the LabBrowser iframe, the frontend nginx
# (or vite dev proxy) prepends "/target" before forwarding to this Flask app.
# Without help, every form action="/auth/login" would escape the iframe and
# hit the React app at /auth/login. This helper inspects the X-Forwarded-Prefix
# header and emits prefixed URLs so the user always stays inside /target/*.
#
# Usage:
#   In Jinja:    {{ lab_url('/auth/login') }}
#   In Python:   from flask import current_app; current_app.lab_url('/auth/login')
# ─────────────────────────────────────────────────────────────────────────────
def lab_url(path: str) -> str:
    if path is None:
        path = "/"
    if not str(path).startswith("/"):
        path = "/" + str(path)
    try:
        prefix = request.headers.get("X-Forwarded-Prefix", "").rstrip("/")
    except RuntimeError:
        # Outside of a request context
        prefix = ""
    return f"{prefix}{path}"


@app.context_processor
def _inject_lab_url():
    """Make `lab_url` available inside every render_template_string call."""
    return {"lab_url": lab_url}


# Expose helper on the app object for direct Python imports.
app.lab_url = lab_url


# ─────────────────────────────────────────────────────────────────────────────
# Channel detection — was this request driven by the lab browser, the
# AttackBox terminal/curl, or something we don't recognise?
#
# Used by every vulnerable route to tag the resulting evidence event with a
# `via` field. Operator-mode missions only count evidence with via="attackbox".
# ─────────────────────────────────────────────────────────────────────────────
import socket as _socket

# Resolve the AttackBox container's IP at startup (best-effort — it may not
# yet be running when the target-agent boots).
_ATTACKBOX_IPS: set[str] = set()
def _refresh_attackbox_ips() -> None:
    for host in ("attackbox", "attense_attackbox"):
        try:
            for info in _socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip:
                    _ATTACKBOX_IPS.add(ip)
        except OSError:
            pass
_refresh_attackbox_ips()


def detect_via() -> str:
    """Classify the current Flask request: 'browser' | 'attackbox' | 'unknown'."""
    try:
        ua  = (request.headers.get("User-Agent") or "")
        prefix = (request.headers.get("X-Forwarded-Prefix") or "").rstrip("/")
        ip  = request.remote_addr or ""
        # Explicit signal from AttackBox (curl alias, ZAP wrapper, etc.)
        if "AttenseAttackBox" in ua:
            return "attackbox"
        # Container-IP signal — refresh cache if we don't know it yet
        if not _ATTACKBOX_IPS:
            _refresh_attackbox_ips()
        if ip in _ATTACKBOX_IPS:
            return "attackbox"
        # Lab browser proxies always set X-Forwarded-Prefix=/target (guided)
        # or /target-op (operator-mode harder backend). Both are browser-driven.
        if prefix in ("/target", "/target-op"):
            return "browser"
    except RuntimeError:
        pass  # outside request context
    return "unknown"


# Make detect_via reachable from blueprint modules without circular imports
app.detect_via = detect_via

# ── Register blueprints ───────────────────────────────────────────────────────
app.register_blueprint(home_bp)
app.register_blueprint(auth_bp,    url_prefix="/auth")
app.register_blueprint(search_bp)
app.register_blueprint(system_bp,  url_prefix="/system")
app.register_blueprint(files_bp,   url_prefix="/files")
app.register_blueprint(profile_bp, url_prefix="/profile")
app.register_blueprint(containment_bp, url_prefix="/containment")

# Operator-mode (HARDER) parallel backend. All 7 module surfaces now
# have a routes_op/ counterpart with stricter logic — same UI, harder
# backend.
app.register_blueprint(home_op_bp,    url_prefix="/op")
app.register_blueprint(auth_op_bp,    url_prefix="/op/auth")
app.register_blueprint(search_op_bp,  url_prefix="/op")
app.register_blueprint(system_op_bp,  url_prefix="/op/system")
app.register_blueprint(files_op_bp,   url_prefix="/op/files")
app.register_blueprint(profile_op_bp, url_prefix="/op/profile")


# ─────────────────────────────────────────────────────────────────────────────
# Lab evidence API — consumed by the red-team backend's check-progress
# endpoint to compute mission progress from manual learner activity.
# ─────────────────────────────────────────────────────────────────────────────
import evidence  # noqa: E402
from flask import jsonify  # noqa: E402


@app.get("/lab/events")
def lab_events():
    """List structured lab events. Filter with ?since=<float> & ?module_id=<id> & ?via=<channel>."""
    try:
        since = float(request.args.get("since", "0") or 0.0)
    except ValueError:
        since = 0.0
    module_id = request.args.get("module_id") or None
    via       = request.args.get("via") or None
    try:
        limit = int(request.args.get("limit", "500"))
    except ValueError:
        limit = 500
    events = evidence.list_events(since=since, module_id=module_id, via=via, limit=limit)
    return jsonify({"events": events, "now": __import__("time").time()})


@app.post("/lab/events/reset")
def lab_events_reset():
    """Clear the in-memory evidence store. Used when a learner restarts a mission."""
    evidence.reset()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# Browser-action capture (Phase 2)
#
# A tiny script is injected into every HTML response from the target-agent.
# It listens to click / submit / page-view events inside the iframe and POSTs
# them to the red-team backend at /api/lab/actions.
#
# The script uses postMessage so we don't have to deal with the iframe's
# cross-origin restrictions when reading the parent's session id — the parent
# Workspace posts the active session_id into the iframe at mount time.
# ─────────────────────────────────────────────────────────────────────────────
_TRACE_JS = """
(function () {
  if (window.__attenseTraceInstalled) return;
  window.__attenseTraceInstalled = true;

  var sessionId = null;
  var backend   = '';   // empty == same origin (proxied through frontend nginx)

  // Receive session_id from the parent Workspace
  window.addEventListener('message', function (e) {
    if (e.data && e.data.type === '__attense_session') {
      sessionId = e.data.session_id || null;
      backend   = e.data.backend   || '';
    }
  });

  function post(payload) {
    payload.session_id = sessionId;
    payload.page = location.pathname + location.search;
    try {
      // The iframe is same-origin via the /target/ proxy, so /api/ works.
      fetch(backend + '/api/lab/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true,
      }).catch(function(){});
    } catch (_) {}
  }

  // Page load
  post({ kind: 'page_view' });

  // Click capture
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t) return;
    var sel = (t.tagName || '').toLowerCase();
    if (t.id) sel += '#' + t.id;
    if (t.name) sel += '[name=' + t.name + ']';
    var text = (t.innerText || t.value || t.title || '').trim().slice(0, 80);
    post({ kind: 'click', selector: sel, text: text });
  }, true);

  // Form submit
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var sel = 'form';
    if (f && f.id) sel += '#' + f.id;
    if (f && f.action) sel += '[action=' + (f.action.split('/').slice(-2).join('/')) + ']';
    var fields = {};
    if (f && f.elements) {
      for (var i = 0; i < f.elements.length; i++) {
        var el = f.elements[i];
        if (!el.name) continue;
        // Don't capture passwords verbatim.
        if (el.type === 'password') { fields[el.name] = '***'; continue; }
        fields[el.name] = (el.value || '').slice(0, 80);
      }
    }
    post({ kind: 'form_submit', selector: sel, extra: { fields: fields } });
  }, true);
})();
"""


@app.get("/lab/__attense_trace.js")
def serve_trace_js():
    """Serve the action-capture script."""
    from flask import Response
    return Response(_TRACE_JS, mimetype="application/javascript")


@app.after_request
def _inject_trace_script(resp):
    """Append a <script> tag pointing at __attense_trace.js to every HTML page
    served by the target-agent. This is how clicks and form submits inside
    the iframe become evidence the red-team backend can read."""
    try:
        ct = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" not in ct:
            return resp
        # Only patch full HTML documents
        body = resp.get_data(as_text=True)
        if "</body>" not in body:
            return resp
        prefix = (request.headers.get("X-Forwarded-Prefix") or "").rstrip("/")
        tag = (
            '<script src="' + prefix + '/lab/__attense_trace.js" '
            'data-attense="trace" defer></script>'
        )
        # Inject just before </body>
        body = body.replace("</body>", tag + "</body>", 1)
        resp.set_data(body)
        # Update content-length if present
        if resp.headers.get("Content-Length"):
            resp.headers["Content-Length"] = str(len(resp.get_data()))
    except Exception:
        pass  # never break a page over telemetry
    return resp

if __name__ == "__main__":
    # Bind to all interfaces inside the container; nginx proxies from port 80.
    app.run(host="0.0.0.0", port=5000, debug=False)
