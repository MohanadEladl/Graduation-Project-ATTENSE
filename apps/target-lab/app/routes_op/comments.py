"""
routes_op/comments.py — Operator-mode STORED XSS (Hard, variant "stored_attempt").

A genuine two-step exploit that a reflected one-liner cannot satisfy:
  1. POST /op/comments  — the comment is PERSISTED to the store.
  2. GET  /op/comments  — every stored comment is rendered RAW (|safe), so a
     stored payload executes for every later viewer.

The goal event `stored_xss_persisted` fires on the GET that renders a stored,
executing payload — proving BOTH persistence and rendering. Reflected evidence
from /op/search (xss_reflected_html_executed) can never complete this variant.

Local lab only: the store is in-memory (reset on restart) and rendering is
intentionally unescaped — that IS the vulnerability under test.
"""
import json
import logging

from flask import Blueprint, request, render_template_string, redirect, current_app

logger = logging.getLogger("target.comments_op")
comments_op_bp = Blueprint("comments_op", __name__)

# In-memory comment store for the local lab (not persisted, not per-user).
_COMMENTS: list = []

_EXEC_TOKENS = ("<script", "onerror=", "onload=", "onclick=", "onmouseover=",
                "onfocus=", "javascript:", "<svg", "<img", "<iframe")

_TEMPLATE = """<!doctype html><html><head><title>Operator Comments</title></head>
<body style="font-family:system-ui;background:#0b0d12;color:#e8ecf5;padding:24px">
  <h2>Operator Comments</h2>
  <form method="post" action="/op/comments">
    <input name="comment" placeholder="Leave a comment" style="width:360px;padding:8px">
    <button>Post</button>
  </form>
  <hr>
  {% for c in comments %}<div class="cmt">{{ c|safe }}</div>{% endfor %}
</body></html>"""


def _executes(text: str) -> bool:
    return any(tok in (text or "").lower() for tok in _EXEC_TOKENS)


@comments_op_bp.route("/comments", methods=["GET", "POST"])
def comments():
    import evidence
    via = current_app.detect_via()

    if request.method == "POST":
        body = request.form.get("comment", "") or request.args.get("comment", "")
        _COMMENTS.append(body)
        logger.info(json.dumps({
            "event": "comment_stored", "endpoint": "/op/comments",
            "len": len(body or ""), "source_ip": request.remote_addr,
        }))
        evidence.record(
            "comment_stored", module_id="xss", path="/op/comments", method="POST",
            source_ip=request.remote_addr, via=via, severity="low",
            extra={"comment": (body or "")[:200], "backend": "operator"},
        )
        return redirect("/op/comments")

    # GET — render all stored comments RAW. If any stored comment executes, the
    # stored payload has both PERSISTED and RENDERED: the stored-XSS goal.
    if any(_executes(c) for c in _COMMENTS):
        evidence.record(
            "stored_xss_persisted", module_id="xss", path="/op/comments", method="GET",
            source_ip=request.remote_addr, via=via, severity="high",
            extra={"stored_count": len(_COMMENTS), "backend": "operator"},
        )
    return render_template_string(_TEMPLATE, comments=_COMMENTS)
