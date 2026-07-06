"""
routes_op/search.py — Operator-mode HARDER reflected XSS.

Same template, but the q parameter goes through a sanitization pass that
strips <script>...</script> blocks (case-insensitive). Event-handler
payloads (onerror=, onload=, javascript: hrefs) STILL pass through and
reflect — that's the bypass the learner has to discover.

Same evidence event types so lab_progress.py is unchanged.
"""
import json
import logging
import re

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.search_op")
search_op_bp = Blueprint("search_op", __name__)

from routes.search import _TEMPLATE  # noqa: E402

_SCRIPT_TAG_RE = re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE)


def _sanitize(q: str) -> str:
    """Strip <script>...</script> tokens; everything else passes through."""
    if not q:
        return q
    return _SCRIPT_TAG_RE.sub("", q)


@search_op_bp.route("/search")
def search():
    raw_q = request.args.get("q", "")
    q     = _sanitize(raw_q)

    logger.info(json.dumps({
        "event":     "search_request",
        "endpoint":  "/op/search",
        "query":     raw_q,
        "sanitized": q,
        "source_ip": request.remote_addr,
        "method":    request.method,
    }))

    import evidence
    via = current_app.detect_via()
    evidence.record(
        "search_used",
        module_id="xss",
        path="/op/search", method="GET",
        source_ip=request.remote_addr,
        via=via,
        extra={"query": raw_q, "backend": "operator"},
    )

    if raw_q:
        low = raw_q.lower()
        # XSS-shaped payload detection runs on the RAW query so learners
        # still get credit for trying <script> even though it's stripped.
        if any(s in low for s in ("<script", "</script", "onerror=", "onload=",
                                  "onclick=", "onmouseover=", "javascript:",
                                  "<svg", "<img ", "<iframe")):
            evidence.record(
                "xss_payload_observed",
                module_id="xss",
                path="/op/search", method="GET",
                source_ip=request.remote_addr,
                via=via,
                severity="medium",
                extra={"query": raw_q[:200], "backend": "operator"},
            )
            # Reflection only fires if the SANITIZED payload still contains
            # an HTML-effective construct — i.e., the bypass succeeded.
            slow = q.lower()
            if any(s in slow for s in ("onerror=", "onload=", "onclick=",
                                       "onmouseover=", "javascript:",
                                       "<svg", "<img ", "<iframe")):
                evidence.record(
                    "reflected_input_detected",
                    module_id="xss",
                    path="/op/search", method="GET",
                    source_ip=request.remote_addr,
                    via=via,
                    severity="high",
                    extra={"query": q[:200], "backend": "operator"},
                )

    return render_template_string(_TEMPLATE, q=q)
