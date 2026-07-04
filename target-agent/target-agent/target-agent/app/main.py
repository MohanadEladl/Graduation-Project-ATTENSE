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

# ── Register blueprints ───────────────────────────────────────────────────────
app.register_blueprint(home_bp)
app.register_blueprint(auth_bp,    url_prefix="/auth")
app.register_blueprint(search_bp)
app.register_blueprint(system_bp,  url_prefix="/system")
app.register_blueprint(files_bp,   url_prefix="/files")
app.register_blueprint(profile_bp, url_prefix="/profile")


# ─────────────────────────────────────────────────────────────────────────────
# Lab evidence API — consumed by the red-team backend's check-progress
# endpoint to compute mission progress from manual learner activity.
# ─────────────────────────────────────────────────────────────────────────────
import evidence  # noqa: E402
from flask import jsonify  # noqa: E402


@app.get("/lab/events")
def lab_events():
    """List structured lab events. Filter with ?since=<float> and ?module_id=<id>."""
    try:
        since = float(request.args.get("since", "0") or 0.0)
    except ValueError:
        since = 0.0
    module_id = request.args.get("module_id") or None
    try:
        limit = int(request.args.get("limit", "500"))
    except ValueError:
        limit = 500
    events = evidence.list_events(since=since, module_id=module_id, limit=limit)
    return jsonify({"events": events, "now": __import__("time").time()})


@app.post("/lab/events/reset")
def lab_events_reset():
    """Clear the in-memory evidence store. Used when a learner restarts a mission."""
    evidence.reset()
    return jsonify({"ok": True})

if __name__ == "__main__":
    # Bind to all interfaces inside the container; nginx proxies from port 80.
    app.run(host="0.0.0.0", port=5000, debug=False)
