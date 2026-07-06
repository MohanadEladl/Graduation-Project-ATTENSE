"""
routes_op/files.py — Operator-mode HARDER traversal + upload.

Traversal:
  * The `path` parameter is rejected outright if it contains `..`.
  * Absolute paths (starting with `/`) ARE accepted — the bypass is to
    pass `/etc/passwd` directly instead of `../../etc/passwd`.

Upload:
  * Hard-blocks .php, .exe, .sh, .py, .pl, .cgi, .jsp, .jspx, .asp, .aspx
  * Allows .phtml, .svg, .html, .htm, .js — those are the bypasses.

Same evidence event types so lab_progress.py is unchanged.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string, current_app

logger = logging.getLogger("target.files_op")
files_op_bp = Blueprint("files_op", __name__)

from routes.files import _READ_PAGE, _UPLOAD_PAGE  # noqa: E402

# Reuse the guided-mode UPLOAD_DIR (already created at import time by routes.files).
import routes.files as _guided_files  # noqa: E402

BASE_DIR    = _guided_files.BASE_DIR
UPLOAD_DIR  = _guided_files.UPLOAD_DIR

# Block list for the harder upload — extensions a real defender would
# blacklist. The intent is the learner has to go AROUND the list (.phtml,
# .svg, .html) to still get a dangerous payload through.
_HARD_BLOCKED_EXT = (
    ".php", ".phps", ".exe", ".sh", ".py", ".pl", ".cgi",
    ".jsp", ".jspx", ".asp", ".aspx",
)
_DANGEROUS_BUT_ACCEPTED = (
    ".phtml", ".svg", ".html", ".htm", ".js",
)


# ── Directory traversal ─────────────────────────────────────────────────────
# Level-gated (Part 5). ?level=easy|medium|hard. Flask decodes %2e%2e to ..,
# so encoded-vs-plain is distinguished from the RAW query string, not the
# decoded value:
#   Easy   (variant "plain")    → literal ../ allowed              → traversal_plain_success
#   Medium (variant "encoded")  → literal ../ blocked; %2e-encoded → traversal_encoded_success
#   Hard   (variant "absolute") → ../ and %2e blocked; /abs path   → traversal_absolute_bypass_success
_SENSITIVE = ("root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:")


@files_op_bp.route("/read")
def read_file():
    raw = request.args.get("path", "readme.txt")          # Flask-decoded
    qs = request.query_string.decode("latin-1", "ignore").lower()  # raw query
    level = (request.args.get("level") or "easy").strip().lower()
    if level in ("absolute", "abs"):
        level = "hard"
    elif level in ("encoded",):
        level = "medium"
    elif level in ("plain",):
        level = "easy"

    import evidence
    via = current_app.detect_via()

    logger.info(json.dumps({
        "event": "file_read_request", "endpoint": "/op/files/read",
        "level": level, "path_param": raw, "source_ip": request.remote_addr,
    }))
    evidence.record(
        "file_viewer_used", module_id="dir_traversal", path="/op/files/read",
        method="GET", source_ip=request.remote_addr, via=via,
        extra={"path_param": raw, "level": level, "backend": "operator"},
    )

    # How the traversal was expressed, read from the RAW query string.
    literal_dotdot = ".." in qs
    encoded_dotdot = "%2e" in qs
    absolute_path = raw.startswith("/")

    low = raw.lower()
    if literal_dotdot or encoded_dotdot or absolute_path or "passwd" in low or "shadow" in low:
        evidence.record(
            "traversal_pattern_observed", module_id="dir_traversal",
            path="/op/files/read", method="GET", source_ip=request.remote_addr,
            via=via, severity="medium",
            extra={"path_param": raw[:200], "level": level, "backend": "operator"},
        )

    # Level gate: reject the forms this difficulty is meant to defeat.
    blocked_reason = None
    if level == "easy":
        pass  # literal ../ allowed
    elif level == "medium":
        if literal_dotdot and not encoded_dotdot:
            blocked_reason = "literal '..' is filtered — try URL-encoding it (%2e%2e%2f)"
    else:  # hard
        if literal_dotdot or encoded_dotdot:
            blocked_reason = "traversal sequences are filtered — try an absolute path (/etc/passwd)"
    if blocked_reason:
        return render_template_string(_READ_PAGE, path=raw, content=f"[ERROR] {blocked_reason}")

    full_path = raw if absolute_path else os.path.join(BASE_DIR, raw)
    try:
        with open(full_path, "r", errors="replace") as f:
            content = f.read(4096)
        if any(s in content for s in _SENSITIVE):
            # Attribute the disclosure to the technique that this level required.
            event = None
            if level == "easy" and literal_dotdot:
                event = "traversal_plain_success"
            elif level == "medium" and encoded_dotdot:
                event = "traversal_encoded_success"
            elif level == "hard" and absolute_path:
                event = "traversal_absolute_bypass_success"
            if event:
                evidence.record(
                    event, module_id="dir_traversal", path="/op/files/read",
                    method="GET", source_ip=request.remote_addr, via=via,
                    severity="critical",
                    extra={"path_param": raw[:200], "level": level, "backend": "operator"},
                )
    except FileNotFoundError:
        content = f"[ERROR] File not found: {full_path}"
    except PermissionError:
        content = f"[ERROR] Permission denied: {full_path}"
    except Exception as exc:
        content = f"[ERROR] {exc}"

    return render_template_string(_READ_PAGE, path=raw, content=content)


# ── File upload ─────────────────────────────────────────────────────────────
@files_op_bp.route("/upload", methods=["GET", "POST"])
def upload_file():
    import evidence
    via = current_app.detect_via()
    evidence.record(
        "file_upload_used",
        module_id="file_upload",
        path="/op/files/upload", method=request.method,
        source_ip=request.remote_addr,
        via=via,
        extra={"backend": "operator"},
    )
    if request.method == "GET":
        return render_template_string(_UPLOAD_PAGE, message="")

    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template_string(
            _UPLOAD_PAGE,
            message='<div class="error-msg">No file selected.</div>',
        )

    filename = file.filename
    fn_lower = filename.lower()

    # HARDER: hard-block obvious server-side execution extensions.
    if any(fn_lower.endswith(ext) for ext in _HARD_BLOCKED_EXT):
        return render_template_string(
            _UPLOAD_PAGE,
            message=f'<div class="error-msg">Extension blocked by policy: {filename}</div>',
        ), 400

    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    logger.warning(json.dumps({
        "event":     "file_upload_saved",
        "filename":  filename,
        "save_path": save_path,
    }))

    evidence.record(
        "file_saved",
        module_id="file_upload",
        path="/op/files/upload", method="POST",
        source_ip=request.remote_addr,
        via=via,
        extra={"filename": filename, "content_type": file.content_type or "",
               "backend": "operator"},
    )

    if any(fn_lower.endswith(ext) for ext in _DANGEROUS_BUT_ACCEPTED):
        evidence.record(
            "dangerous_extension_accepted",
            module_id="file_upload",
            path="/op/files/upload", method="POST",
            source_ip=request.remote_addr,
            via=via,
            severity="high",
            extra={"filename": filename, "backend": "operator"},
        )
        evidence.record(
            "unrestricted_upload_detected",
            module_id="file_upload",
            path="/op/files/upload", method="POST",
            source_ip=request.remote_addr,
            via=via,
            severity="high",
            learner_message=(
                "A bypass-style extension was accepted by the upload form "
                "even though .php is blocked."
            ),
            extra={"filename": filename, "backend": "operator"},
        )

    served_url = current_app.lab_url(f"/static/uploads/{filename}")
    msg = (
        '<div class="result-msg">&#9989; File saved successfully'
        f'<br/>Path: {save_path}'
        f'<br/>Open: <a href="{served_url}">{served_url}</a>'
        '</div>'
    )
    return render_template_string(_UPLOAD_PAGE, message=msg)
