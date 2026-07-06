"""
routes_op/search.py — Operator-mode reflected XSS with REAL difficulty levels.

The active difficulty is selected with ?level=easy|medium (default easy). Each
level reflects the query in a DIFFERENT context and emits a DIFFERENT goal event
so lab_progress's variant-aware goal-trigger engine can tell them apart:

  Easy   (variant "reflected")          → HTML body context.
         <script> is stripped, but an event-handler/img/svg payload reflects raw
         and executes.  Goal event: xss_reflected_html_executed.

  Medium (variant "alternate_context")  → double-quoted ATTRIBUTE context.
         < and > are HTML-escaped (so a body <img>/<svg> is inert), quotes are
         NOT — the student must break OUT of the attribute with a quote + event
         handler.  Goal event: xss_attribute_context_bypass.

Stored XSS (Hard, variant "stored_attempt") lives in routes_op/comments.py.

`xss_payload_observed` still fires for ANY xss-shaped attempt (evidence/quality),
but it is NO LONGER a completion trigger — completion is the level-specific event.
"""
import json
import logging
import re

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.search_op")
search_op_bp = Blueprint("search_op", __name__)

from routes.search import _TEMPLATE  # noqa: E402  (Easy = HTML body context)

_SCRIPT_TAG_RE = re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"on\w+\s*=", re.IGNORECASE)

# Any XSS-shaped token — used only to record the (non-completing) attempt event.
_XSS_SHAPES = ("<script", "</script", "onerror=", "onload=", "onclick=",
               "onmouseover=", "onfocus=", "javascript:", "<svg", "<img", "<iframe")
# Constructs that actually execute when reflected raw in an HTML BODY.
_BODY_EXEC = ("onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
              "javascript:", "<svg", "<img", "<iframe")

# Medium reflects into value="__Q__"; escape angle brackets so a body-context
# payload is inert, but leave quotes so an attribute breakout is possible.
_MEDIUM_TEMPLATE = """<!doctype html><html><head><title>Operator Search</title></head>
<body style="font-family:system-ui;background:#0b0d12;color:#e8ecf5;padding:24px">
  <h2>Operator Search</h2>
  <form method="get" action="/op/search">
    <input type="hidden" name="level" value="medium">
    <input name="q" value="__Q__" style="width:360px;padding:8px">
    <button>Search</button>
  </form>
  <p>Results for: __Q__</p>
</body></html>"""


def _sanitize_body(q: str) -> str:
    """Easy context: strip <script>...</script>; everything else passes through."""
    return _SCRIPT_TAG_RE.sub("", q or "")


def _escape_angles(q: str) -> str:
    """Medium context: neutralize a body payload but leave quotes for breakout."""
    return (q or "").replace("<", "&lt;").replace(">", "&gt;")


def _body_executes(sanitized: str) -> bool:
    return any(tok in sanitized.lower() for tok in _BODY_EXEC)


def _attribute_breakout(raw: str) -> bool:
    """True when the raw query breaks out of a double-quoted attribute — a quote
    followed by an event handler (`" onmouseover=…`) or a tag breakout (`">…`)."""
    if '"' not in raw:
        return False
    after = raw.split('"', 1)[1]
    return bool(_EVENT_HANDLER_RE.search(after)) or '">' in raw


@search_op_bp.route("/search")
def search():
    raw_q = request.args.get("q", "")
    level = (request.args.get("level") or "easy").strip().lower()
    if level in ("alternate_context", "attribute", "alt"):
        level = "medium"
    elif level in ("reflected",):
        level = "easy"

    import evidence
    via = current_app.detect_via()

    logger.info(json.dumps({
        "event": "search_request", "endpoint": "/op/search",
        "level": level, "query": raw_q, "source_ip": request.remote_addr,
    }))
    evidence.record(
        "search_used", module_id="xss", path="/op/search", method="GET",
        source_ip=request.remote_addr, via=via,
        extra={"query": raw_q, "level": level, "backend": "operator"},
    )

    if raw_q and any(tok in raw_q.lower() for tok in _XSS_SHAPES):
        # Non-completing attempt marker (evidence + quality only).
        evidence.record(
            "xss_payload_observed", module_id="xss", path="/op/search", method="GET",
            source_ip=request.remote_addr, via=via, severity="medium",
            extra={"query": raw_q[:200], "level": level, "backend": "operator"},
        )

    if level == "medium":
        # MEDIUM — attribute context: only an attribute breakout executes.
        if raw_q and _attribute_breakout(raw_q):
            evidence.record(
                "xss_attribute_context_bypass", module_id="xss",
                path="/op/search", method="GET", source_ip=request.remote_addr,
                via=via, severity="high",
                extra={"query": raw_q[:200], "level": "medium", "backend": "operator"},
            )
        return render_template_string(_MEDIUM_TEMPLATE.replace("__Q__", _escape_angles(raw_q)))

    # EASY — HTML body context: <script> stripped, event-handler/img/svg execute.
    body_q = _sanitize_body(raw_q)
    if raw_q and _body_executes(body_q):
        evidence.record(
            "xss_reflected_html_executed", module_id="xss",
            path="/op/search", method="GET", source_ip=request.remote_addr,
            via=via, severity="high",
            extra={"query": body_q[:200], "level": "easy", "backend": "operator"},
        )
    return render_template_string(_TEMPLATE, q=body_q)
