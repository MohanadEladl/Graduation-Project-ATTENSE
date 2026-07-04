"""
routes/profile.py - User profile + update endpoint.

[VULN APP-05] CSRF - /profile/update accepts POSTs with no CSRF token,
no Origin/Referer enforcement.

[VULN APP-01 variant] Stored XSS via the email field - session-scoped. An
XSS-shaped email is stashed per mission session_id (see `_stored_xss_by_session`)
rather than written into the shared `_PROFILES` dict, so it's visible only to
the learner who planted it (persists across their own page refreshes) and
never leaks to other concurrent learners. `clear_session()` reverts it back
to normal; called from target-agent's `/lab/events/reset` handler so ending
or restarting the mission resets the module to a clean, replayable state.
"""
import json
import logging
import hmac
import secrets

from flask import Blueprint, request, render_template_string, session, current_app, abort

import containment
import route_security

logger = logging.getLogger("target.profile")
profile_bp = Blueprint("profile", __name__)

_PROFILES: dict[str, dict] = {
    "admin": {"email": "admin@lab.local", "role": "administrator"},
    "operator": {"email": "operator@lab.local", "role": "operator"},
    "guest": {"email": "guest@lab.local", "role": "guest"},
    "alice": {"email": "alice@lab.local", "role": "user"},
}

# session_id -> stashed XSS-shaped email, kept separate from _PROFILES so a
# stored-XSS attempt never mutates the shared account data other modules
# (e.g. csrf) rely on. Cleared by clear_session() on mission reset/finish.
_stored_xss_by_session: dict[str, str] = {}


def clear_session(session_id: str) -> None:
    """Revert a session's stashed stored-XSS payload back to normal."""
    _stored_xss_by_session.pop(session_id, None)

_PROFILE_PAGE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>My Account - AcmeCorp</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;}

.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;gap:12px;}
.topbar .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#06b6d4,#0ea5e9);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:14px;}
.topbar span{font-size:15px;font-weight:600;color:#e2e8f0;}
.topbar nav{margin-left:auto;display:flex;gap:16px;font-size:13px;}

.container{max-width:600px;margin:0 auto;padding:40px 24px;}
h2{font-size:20px;font-weight:600;color:#e2e8f0;margin-bottom:24px;}

.profile-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:28px;margin-bottom:24px;}
.avatar-row{display:flex;align-items:center;gap:16px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid rgba(255,255,255,.06);}
.avatar{width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#06b6d4,#6366f1);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff;}
.avatar-info h3{font-size:16px;font-weight:600;color:#e2e8f0;}
.avatar-info p{font-size:12px;color:#64748b;margin-top:2px;}
.role-badge{display:inline-block;font-size:10px;background:rgba(6,182,212,.12);border:1px solid rgba(6,182,212,.3);color:#22d3ee;padding:3px 10px;border-radius:20px;margin-top:4px;letter-spacing:.04em;text-transform:uppercase;}

.info-grid{display:grid;grid-template-columns:120px 1fr;gap:12px;font-size:13px;}
.info-grid .label{color:#64748b;font-weight:500;}
.info-grid .value{color:#e2e8f0;}

.update-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:28px;}
.update-card h3{font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:6px;}
.update-card .sub{font-size:12px;color:#64748b;margin-bottom:18px;}

.field{margin-bottom:16px;}
.field label{display:block;font-size:12px;font-weight:500;color:#94a3b8;margin-bottom:6px;}
.field input{width:100%;padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;}
.field input:focus{border-color:rgba(6,182,212,.5);}

.btn{padding:10px 24px;background:linear-gradient(135deg,#06b6d4,#0ea5e9);border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;cursor:pointer;}

.success-msg{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);border-radius:8px;padding:10px 14px;margin-top:16px;font-size:13px;color:#4ade80;text-align:center;}

.back{display:inline-block;margin-top:24px;font-size:12px;}
</style>
</head><body>

<div class="topbar">
  <div class="logo">A</div>
  <span>AcmeCorp</span>
  <nav>
    <a href="{{ lab_url('/') }}">Home</a>
    <a href="{{ lab_url('/profile/') }}">Profile</a>
    <a href="{{ lab_url('/auth/logout') }}">Sign Out</a>
  </nav>
</div>

<div class="container">
  <h2>&#128100; My Account</h2>

  <div class="profile-card">
    <div class="avatar-row">
      <div class="avatar">{{ user_initial }}</div>
      <div class="avatar-info">
        <h3>{{ user }}</h3>
        <p>{{ email|safe }}</p>
        <span class="role-badge">{{ role }}</span>
      </div>
    </div>
    <div class="info-grid">
      <span class="label">Username</span><span class="value">{{ user }}</span>
      <span class="label">Email</span><span class="value">{{ email }}</span>
      <span class="label">Role</span><span class="value">{{ role }}</span>
      <span class="label">Status</span><span class="value" style="color:#4ade80;">Active</span>
    </div>
  </div>

  <div class="update-card">
    <h3>Update Email Address</h3>
    <div class="sub">Change your notification email below</div>
    <form method="POST" action="{{ lab_url('/profile/update') }}">
      <div class="field">
        <label>New Email Address</label>
        <input name="email" value="{{ email }}" placeholder="new@email.com"/>
      </div>
      {% if csrf_token %}<input type="hidden" name="_csrf_token" value="{{ csrf_token }}"/>{% endif %}
      <button type="submit" class="btn">Save Changes</button>
    </form>
    {{ message|safe }}
  </div>

  <a href="{{ lab_url('/') }}" class="back">&larr; Back to Portal</a>
</div>
</body></html>
"""


@profile_bp.route("/")
def profile():
    user = session.get("user", "guest")
    data = _PROFILES.get(user, _PROFILES["guest"])
    csrf_token = ""
    if containment.is_enabled("csrf_protection"):
        csrf_token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    import evidence
    sid = current_app.current_session_id()
    evidence.record(
        "route_discovered",
        module_id="csrf",
        path="/profile/", method="GET",
        source_ip=current_app.fake_attacker_ip(),
        via=current_app.detect_via(),
        session_id=sid,
        extra={"user": user},
    )

    # Session-scoped stored XSS: if this session planted a payload earlier,
    # show them (and only them) that persisted, unescaped value - this is
    # the "second request" the stored_attempt variant's task ladder expects.
    display_email = data["email"]
    stashed = _stored_xss_by_session.get(sid) if sid else None
    if stashed is not None:
        display_email = stashed
        evidence.record(
            "reflected_input_detected",
            module_id="xss",
            path="/profile/", method="GET",
            source_ip=current_app.fake_attacker_ip(),
            via=current_app.detect_via(),
            session_id=sid,
            severity="high",
            extra={"user": user, "field": "email"},
        )

    return render_template_string(
        _PROFILE_PAGE,
        user=user, email=display_email, role=data["role"], message="",
        user_initial=(user[0].upper() if user else "G"),
        csrf_token=csrf_token,
    )


@profile_bp.route("/update", methods=["POST"])
def update():
    # [VULN] No CSRF token check
    user = session.get("user", "guest")
    email = request.form.get("email", "")
    referer = request.headers.get("Referer", "none")
    origin = request.headers.get("Origin", "none")

    logger.warning(json.dumps({
        "event": "profile_update",
        "endpoint": "/profile/update",
        "user": user,
        "new_email": email,
        "source_ip": current_app.fake_attacker_ip(),
        "referer": referer,
        "origin": origin,
    }))

    # Lab evidence
    import evidence
    evidence.record(
        "profile_update_used",
        module_id="csrf",
        path="/profile/update", method="POST",
        source_ip=current_app.fake_attacker_ip(),
        via=current_app.detect_via(),
        session_id=current_app.current_session_id(),
        extra={"user": user, "new_email": email, "referer": referer},
    )
    # No anti-CSRF token field is ever sent - every request is by definition missing one
    supplied_token = request.form.get("_csrf_token") or request.form.get("csrf_token") or ""
    expected_token = session.get("csrf_token", "")
    has_token = bool(
        supplied_token
        and expected_token
        and hmac.compare_digest(supplied_token, expected_token)
    )
    if containment.is_enabled("csrf_protection") and not has_token:
        logger.warning(json.dumps({
            "event": "csrf_request_blocked",
            "endpoint": "/profile/update",
            "user": user,
            "source_ip": current_app.fake_attacker_ip(),
        }))
        abort(403)
    if not has_token:
        evidence.record(
            "csrf_token_missing",
            module_id="csrf",
            path="/profile/update", method="POST",
            source_ip=current_app.fake_attacker_ip(),
        via=current_app.detect_via(),
        session_id=current_app.current_session_id(),
            severity="high",
            extra={"user": user, "referer": referer},
        )
    # If the request came from the lure page, mark a forged CSRF submission
    if "/evil/csrf-demo" in referer:
        evidence.record(
            "csrf_lure_submitted",
            module_id="csrf",
            path="/profile/update", method="POST",
            source_ip=current_app.fake_attacker_ip(),
        via=current_app.detect_via(),
        session_id=current_app.current_session_id(),
            severity="high",
            extra={"user": user, "referer": referer},
        )

    sid = current_app.current_session_id()

    # Session-scoped stored XSS: an XSS-shaped email is stashed per session
    # instead of written into the shared _PROFILES dict, so it's visible only
    # to the learner who planted it and never mutates the account data the
    # csrf module relies on.
    if sid and route_security.has_xss_payload(email):
        _stored_xss_by_session[sid] = email
        evidence.record(
            "xss_payload_observed",
            module_id="xss",
            path="/profile/update", method="POST",
            source_ip=current_app.fake_attacker_ip(),
            via=current_app.detect_via(),
            session_id=sid,
            extra={"user": user, "field": "email"},
        )
        display_email = email
    elif user in _PROFILES:
        old_email = _PROFILES[user]["email"]
        _PROFILES[user]["email"] = email
        if not has_token and old_email != email:
            evidence.record(
                "profile_changed_without_csrf",
                module_id="csrf",
                path="/profile/update", method="POST",
                source_ip=current_app.fake_attacker_ip(),
        via=current_app.detect_via(),
        session_id=sid,
                severity="critical",
                extra={"user": user, "old_email": old_email, "new_email": email},
            )
        display_email = _PROFILES.get(user, _PROFILES["guest"])["email"]
    else:
        display_email = _PROFILES["guest"]["email"]

    msg = '<div class="success-msg">&#9989; Email updated successfully.</div>'
    return render_template_string(
        _PROFILE_PAGE,
        user=user, email=display_email, role=_PROFILES.get(user, _PROFILES["guest"])["role"], message=msg,
        user_initial=(user[0].upper() if user else "G"),
        csrf_token=(session.get("csrf_token", "") if containment.is_enabled("csrf_protection") else ""),
    )
