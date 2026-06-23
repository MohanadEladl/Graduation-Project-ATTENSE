"""
auth.py — Sign-in / sign-out flow.

Vulnerabilities (intentional, lab):
  • APP-06 / no rate limit                  ← brute-force friendly
  • APP-06 / username enumeration            ← distinct error messages
  • APP-08 / weak password set               ← admin / password123 etc
  • APP-06 / no account lockout
  • APP-12 / session fixation                ← session.user set on login

Templates use {{ lab_url('/path') }} so links/forms work both at the bare
target-agent host AND through the lab-browser proxy at /target/...
"""
import json
import logging

from flask import Blueprint, request, render_template_string, session, redirect, current_app

logger = logging.getLogger("target.auth")

auth_bp = Blueprint("auth", __name__)

_USERS = {
    "admin":    "password123",
    "operator": "lab2024",
    "guest":    "guest",
    "alice":    "alice123",
    "bob":      "qwerty",
    "service":  "service",
}

_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign In · Lab</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
  .login-shell{width:100%;max-width:440px;}
  .brand{text-align:center;margin-bottom:32px;}
  .brand-mark{width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#dc2626,#7c3aed);margin:0 auto 12px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:22px;}
  .brand-name{font-size:13px;letter-spacing:.32em;color:#94a3b8;text-transform:uppercase;}
  .login-card{background:rgba(15,23,42,.95);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:28px;}
  h1{margin:0 0 4px;font-size:22px;}
  .sub{color:#94a3b8;font-size:13px;margin-bottom:22px;}
  label{display:block;font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;margin-bottom:6px;}
  input{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);border-radius:8px;padding:10px 12px;color:#e2e8f0;font-size:14px;margin-bottom:14px;box-sizing:border-box;}
  input:focus{outline:none;border-color:#dc2626;}
  button{width:100%;background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;border:none;padding:11px;border-radius:8px;font-weight:700;letter-spacing:.05em;cursor:pointer;}
  .error-msg{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:10px;border-radius:8px;font-size:13px;margin-bottom:14px;}
  .back{display:block;text-align:center;margin-top:18px;color:#64748b;font-size:12px;text-decoration:none;}
  .back:hover{color:#94a3b8;}
</style>
</head><body>
<div class="login-shell">
  <div class="brand">
    <div class="brand-mark">A</div>
    <div class="brand-name">Lab</div>
  </div>
  <div class="login-card">
    <h1>Sign In</h1>
    <p class="sub">Use your assigned operator credentials.</p>
    {{ error|safe }}
    <form method="POST" action="{{ lab_url('/auth/login') }}">
      <label>Username</label>
      <input name="username" autocomplete="username" value="{{ username }}" required autofocus>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign In</button>
    </form>
    <a href="{{ lab_url('/') }}" class="back">&larr; Back</a>
  </div>
</div>
</body></html>"""


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(_LOGIN_PAGE, username="", error="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # [VULN] No rate limiting — brute force freely
    if _USERS.get(username) == password:
        session["user"] = username
        logger.info(json.dumps({
            "event": "login_success",
            "endpoint": "/auth/login",
            "username": username,
            "source_ip": request.remote_addr,
        }))
        # Lab evidence
        import evidence
        evidence.record(
            "login_success",
            module_id="brute_force",
            path="/auth/login", method="POST",
            source_ip=request.remote_addr,
        via=current_app.detect_via(),
            extra={"username": username},
        )
        # Mark a credential pair as found (the success criterion)
        evidence.record(
            "credential_found",
            module_id="brute_force",
            path="/auth/login", method="POST",
            source_ip=request.remote_addr,
        via=current_app.detect_via(),
            severity="high",
            learner_message=f"Valid credential confirmed: {username} / (correct password).",
            extra={"username": username},
        )
        return redirect(current_app.lab_url("/profile/"))
    else:
        # [VULN] Username enumeration
        if username in _USERS:
            msg = ('<div class="error-msg">Incorrect password for '
                   '<strong>%s</strong></div>') % username
        else:
            msg = '<div class="error-msg">Account not found</div>'

        logger.warning(json.dumps({
            "event": "login_failure",
            "endpoint": "/auth/login",
            "username": username,
            "source_ip": request.remote_addr,
        }))
        # Lab evidence (drives brute_force_pattern detection)
        import evidence
        evidence.record(
            "login_failed",
            module_id="brute_force",
            path="/auth/login", method="POST",
            source_ip=request.remote_addr,
        via=current_app.detect_via(),
            extra={"username": username, "known_user": username in _USERS},
        )
        return render_template_string(
            _LOGIN_PAGE, username=username, error=msg
        ), 401


@auth_bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(current_app.lab_url("/"))
