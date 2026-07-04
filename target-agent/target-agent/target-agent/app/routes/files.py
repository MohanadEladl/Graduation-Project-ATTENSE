"""
routes/files.py – File read and upload endpoints.

[VULN APP-03] Directory traversal — `path` concatenated to base dir, no
              normalization.
[VULN APP-04] Unrestricted file upload — any filename, any content. Files
              are stored only (NOT executed by Flask). Educational copy
              should call this "Unrestricted dangerous file upload", not
              "RCE", because we do not pipe these files to a runtime.
"""
import json
import logging
import os

from flask import Blueprint, request, render_template_string
from werkzeug.utils import secure_filename  # noqa: F401  (kept for future use)

logger   = logging.getLogger("target.files")
files_bp = Blueprint("files", __name__)

BASE_DIR    = "/app/static/"
UPLOAD_DIR  = "/app/static/uploads/"
os.makedirs(UPLOAD_DIR, exist_ok=True)

_README = os.path.join(BASE_DIR, "readme.txt")
if not os.path.exists(_README):
    with open(_README, "w") as f:
        f.write("ATTENSE Lab Target - static readme\n")


# ── Directory Traversal page ────────────────────────────────────────────────
_READ_PAGE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Document Viewer — AcmeCorp</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;}

.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;gap:12px;}
.topbar .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#22c55e,#16a34a);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:14px;}
.topbar span{font-size:15px;font-weight:600;color:#e2e8f0;}

.container{max-width:760px;margin:0 auto;padding:40px 24px;}
h2{font-size:20px;font-weight:600;color:#e2e8f0;margin-bottom:6px;}
.sub{font-size:13px;color:#64748b;margin-bottom:24px;}

.viewer-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:24px;margin-bottom:20px;}
.viewer-card h3{font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:14px;}

.input-row{display:flex;gap:8px;}
.input-row input{flex:1;padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e2e8f0;font-size:13px;font-family:monospace;outline:none;}
.input-row input:focus{border-color:rgba(34,197,94,.5);}
.input-row button{padding:10px 20px;background:linear-gradient(135deg,#22c55e,#16a34a);border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;cursor:pointer;}

.file-output{margin-top:16px;background:#0a0c12;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:16px;font-family:'Consolas','Courier New',monospace;font-size:12px;color:#86efac;white-space:pre-wrap;max-height:350px;overflow:auto;line-height:1.5;}

.quick-links{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;}
.quick-links a{font-size:11px;padding:5px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:6px;color:#94a3b8;}
.quick-links a:hover{border-color:rgba(34,197,94,.3);color:#4ade80;}

.back{display:inline-block;margin-top:24px;font-size:12px;}
</style>
</head><body>

<div class="topbar">
  <div class="logo">&#128196;</div>
  <span>Document Center</span>
</div>

<div class="container">
  <h2>&#128196; Document Viewer</h2>
  <div class="sub">Browse and read files from the internal repository</div>

  <div class="viewer-card">
    <h3>Open Document</h3>
    <form method="GET" action="{{ lab_url('/files/read') }}">
      <div class="input-row">
        <input name="path" value="{{ path }}" placeholder="Enter file path (e.g. readme.txt)"/>
        <button type="submit">Read File</button>
      </div>
    </form>

    <div class="quick-links">
      <a href="{{ lab_url('/files/read?path=readme.txt') }}">readme.txt</a>
    </div>

    <div class="file-output">{{ content }}</div>
  </div>

  <a href="{{ lab_url('/') }}" class="back">&larr; Back to Portal</a>
</div>
</body></html>
"""


@files_bp.route("/read")
def read_file():
    path = request.args.get("path", "readme.txt")

    logger.info(json.dumps({
        "event": "file_read_request",
        "endpoint": "/files/read",
        "path_param": path,
        "source_ip": request.remote_addr,
    }))

    import evidence
    evidence.record(
        "file_viewer_used",
        module_id="dir_traversal",
        path="/files/read", method="GET",
        source_ip=request.remote_addr,
        extra={"path_param": path},
    )
    # Detect traversal attempts
    low = path.lower()
    if (".." in path) or "%2e%2e" in low or path.startswith("/etc/") \
            or path.startswith("/proc/") or "passwd" in low or "shadow" in low:
        evidence.record(
            "traversal_pattern_observed",
            module_id="dir_traversal",
            path="/files/read", method="GET",
            source_ip=request.remote_addr,
            severity="medium",
            extra={"path_param": path[:200]},
        )

    full_path = BASE_DIR + path  # [VULN] no normalization
    try:
        with open(full_path, "r", errors="replace") as f:
            content = f.read(4096)
        logger.info(json.dumps({
            "event": "file_read_success",
            "resolved_path": full_path,
        }))
        # If file content looks like /etc/passwd or similar sensitive material
        SENSITIVE = ("root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:")
        if any(s in content for s in SENSITIVE):
            evidence.record(
                "sensitive_file_disclosed",
                module_id="dir_traversal",
                path="/files/read", method="GET",
                source_ip=request.remote_addr,
                severity="critical",
                extra={"path_param": path[:200]},
            )
    except FileNotFoundError:
        content = f"[ERROR] File not found: {full_path}"
    except PermissionError:
        content = f"[ERROR] Permission denied: {full_path}"
    except Exception as exc:
        content = f"[ERROR] {exc}"

    return render_template_string(_READ_PAGE, path=path, content=content)


# ── File upload page ────────────────────────────────────────────────────────
_UPLOAD_PAGE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>File Upload — AcmeCorp Support</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;}

.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;gap:12px;}
.topbar .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#a855f7,#7c3aed);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:14px;}
.topbar span{font-size:15px;font-weight:600;color:#e2e8f0;}

.container{max-width:600px;margin:0 auto;padding:40px 24px;}
h2{font-size:20px;font-weight:600;color:#e2e8f0;margin-bottom:6px;}
.sub{font-size:13px;color:#64748b;margin-bottom:24px;}

.upload-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:28px;text-align:center;}
.upload-card h3{font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:16px;}

.drop-zone{border:2px dashed rgba(168,85,247,.3);border-radius:12px;padding:40px 20px;margin-bottom:20px;}
.drop-zone:hover{border-color:rgba(168,85,247,.6);}
.drop-zone .icon{font-size:36px;margin-bottom:10px;}
.drop-zone p{font-size:13px;color:#94a3b8;margin-bottom:14px;}
.drop-zone input[type=file]{font-size:13px;color:#c8cdd8;}

.btn{padding:11px 28px;background:linear-gradient(135deg,#a855f7,#7c3aed);border:none;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;}

.result-msg{margin-top:20px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:12px 16px;font-size:13px;color:#4ade80;text-align:left;font-family:monospace;word-break:break-all;}
.result-msg a{color:#86efac;}
.error-msg{margin-top:20px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:12px 16px;font-size:13px;color:#f87171;}

.back{display:inline-block;margin-top:24px;font-size:12px;}
</style>
</head><body>

<div class="topbar">
  <div class="logo">&#128229;</div>
  <span>Support Center</span>
</div>

<div class="container">
  <h2>&#128229; Submit Attachment</h2>
  <div class="sub">Upload files for your support ticket or document review</div>

  <div class="upload-card">
    <h3>Choose a File</h3>
    <form method="POST" action="{{ lab_url('/files/upload') }}" enctype="multipart/form-data">
      <div class="drop-zone">
        <div class="icon">&#128193;</div>
        <p>Select a file to upload</p>
        <input type="file" name="file"/>
      </div>
      <button type="submit" class="btn">Upload File</button>
    </form>
    {{ message|safe }}
  </div>

  <a href="{{ lab_url('/') }}" class="back">&larr; Back to Portal</a>
</div>
</body></html>
"""


@files_bp.route("/upload", methods=["GET", "POST"])
def upload_file():
    import evidence
    evidence.record(
        "file_upload_used",
        module_id="file_upload",
        path="/files/upload", method=request.method,
        source_ip=request.remote_addr,
    )
    if request.method == "GET":
        return render_template_string(_UPLOAD_PAGE, message="")

    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template_string(
            _UPLOAD_PAGE,
            message='<div class="error-msg">No file selected.</div>',
        )

    filename = file.filename  # [VULN] original filename used as-is
    save_path = os.path.join(UPLOAD_DIR, filename)

    logger.info(json.dumps({
        "event": "file_upload_attempt",
        "endpoint": "/files/upload",
        "filename": filename,
        "content_type": file.content_type,
        "source_ip": request.remote_addr,
    }))

    # [VULN] No extension check, no MIME validation, no size limit, no rename
    file.save(save_path)

    logger.warning(json.dumps({
        "event": "file_upload_saved",
        "filename": filename,
        "save_path": save_path,
    }))

    # Lab evidence
    import evidence
    evidence.record(
        "file_saved",
        module_id="file_upload",
        path="/files/upload", method="POST",
        source_ip=request.remote_addr,
        extra={"filename": filename, "content_type": file.content_type or ""},
    )
    DANGEROUS_EXT = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx",
                     ".sh", ".py", ".pl", ".cgi", ".html", ".htm", ".svg",
                     ".js", ".exe")
    fn_lower = filename.lower()
    if any(fn_lower.endswith(ext) for ext in DANGEROUS_EXT):
        evidence.record(
            "dangerous_extension_accepted",
            module_id="file_upload",
            path="/files/upload", method="POST",
            source_ip=request.remote_addr,
            severity="high",
            extra={"filename": filename},
        )
        evidence.record(
            "unrestricted_upload_detected",
            module_id="file_upload",
            path="/files/upload", method="POST",
            source_ip=request.remote_addr,
            severity="high",
            learner_message=(
                "An executable-style extension was accepted by the upload form. "
                "This is unrestricted dangerous file upload."
            ),
            extra={"filename": filename},
        )

    from flask import current_app
    served_url = current_app.lab_url(f"/static/uploads/{filename}")
    msg = (
        '<div class="result-msg">&#9989; File saved successfully'
        f'<br/>Path: {save_path}'
        f'<br/>Open: <a href="{served_url}">{served_url}</a>'
        '</div>'
    )
    return render_template_string(_UPLOAD_PAGE, message=msg)
