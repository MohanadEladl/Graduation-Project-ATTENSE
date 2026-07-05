"""
routes_op/profile.py — Operator-mode HARDER CSRF.

Adds a Referer/Origin check on /op/profile/update:
  * Reject if neither Referer nor Origin is present
  * Reject if Origin is set and is not target-agent / red-team-frontend
  * Accept if Referer ends with /profile/  (i.e. the legitimate page)
  * Accept if Referer ends with /evil/csrf-demo (the in-lab lure — same
    origin so we still allow it, BUT we tag csrf_lure_submitted)

Bypass: from the AttackBox, learner sends a curl with
  -H 'Referer: http://target-agent/profile/'
which spoofs the legitimate referer and gets through. From the lure
button click in the iframe, the same path works because the lure is on
target-agent (same origin).

Same evidence event types so lab_progress.py is unchanged. The harder
backend now also requires a `_csrf_token` param OR a valid Referer to
*succeed* — but we still credit `csrf_token_missing` if no token is
present, so learners get partial credit for spotting the design.
"""
import json
import logging

from flask import Blueprint, request, render_template_string, session, current_app

logger = logging.getLogger("target.profile_op")
profile_op_bp = Blueprint("profile_op", __name__)

from routes.profile import _PROFILE_PAGE, _PROFILES  # noqa: E402

_ALLOWED_REFERER_ENDS = ("/profile/", "/evil/csrf-demo")


def _origin_ok(origin: str) -> bool:
    if not origin:
        return True   # no Origin header → don't block (curl, hydra, etc.)
    return ("target-agent" in origin) or ("red-team-frontend" in origin) \
        or ("localhost" in origin)


def _referer_ok(referer: str) -> bool:
    if not referer:
        return False
    return any(referer.rstrip("/").endswith(end.rstrip("/")) for end in _ALLOWED_REFERER_ENDS)


@profile_op_bp.route("/")
def profile():
    user = session.get("user", "guest")
    data = _PROFILES.get(user, _PROFILES["guest"])
    import evidence
    evidence.record(
        "route_discovered",
        module_id="csrf",
        path="/op/profile/", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        extra={"user": user, "backend": "operator"},
    )
    return render_template_string(
        _PROFILE_PAGE,
        user=user, email=data["email"], role=data["role"], message="",
        user_initial=(user[0].upper() if user else "G"),
    )


@profile_op_bp.route("/update", methods=["POST"])
def update():
    user    = session.get("user", "guest")
    email   = request.form.get("email", "")
    referer = request.headers.get("Referer", "")
    origin  = request.headers.get("Origin",  "")

    logger.warning(json.dumps({
        "event":      "profile_update",
        "endpoint":   "/op/profile/update",
        "user":       user,
        "new_email":  email,
        "source_ip":  request.remote_addr,
        "referer":    referer or "(none)",
        "origin":     origin or "(none)",
    }))

    import evidence
    via = current_app.detect_via()

    evidence.record(
        "profile_update_used",
        module_id="csrf",
        path="/op/profile/update", method="POST",
        source_ip=request.remote_addr,
        via=via,
        extra={"user": user, "new_email": email, "referer": referer or "(none)",
               "backend": "operator"},
    )

    has_token = bool(request.form.get("_csrf_token") or request.form.get("csrf_token"))
    if not has_token:
        evidence.record(
            "csrf_token_missing",
            module_id="csrf",
            path="/op/profile/update", method="POST",
            source_ip=request.remote_addr,
            via=via,
            severity="high",
            extra={"user": user, "referer": referer or "(none)", "backend": "operator"},
        )

    if "/evil/csrf-demo" in referer:
        evidence.record(
            "csrf_lure_submitted",
            module_id="csrf",
            path="/op/profile/update", method="POST",
            source_ip=request.remote_addr,
            via=via,
            severity="high",
            extra={"user": user, "referer": referer, "backend": "operator"},
        )

    # HARDER: enforce a Referer/Origin sanity check. The legitimate
    # /profile/ flow passes (Referer ends with /profile/). The in-lab
    # lure also passes (Referer ends with /evil/csrf-demo). External
    # cross-origin attempts are rejected.
    if not _origin_ok(origin):
        return render_template_string(
            _PROFILE_PAGE,
            user=user,
            email=_PROFILES.get(user, _PROFILES["guest"])["email"],
            role=_PROFILES.get(user, _PROFILES["guest"])["role"],
            message='<div class="error-msg">Cross-origin request blocked</div>',
            user_initial=(user[0].upper() if user else "G"),
        ), 403

    if not has_token and not _referer_ok(referer):
        return render_template_string(
            _PROFILE_PAGE,
            user=user,
            email=_PROFILES.get(user, _PROFILES["guest"])["email"],
            role=_PROFILES.get(user, _PROFILES["guest"])["role"],
            message='<div class="error-msg">CSRF check failed: missing token and bad Referer</div>',
            user_initial=(user[0].upper() if user else "G"),
        ), 403

    if user in _PROFILES:
        old_email = _PROFILES[user]["email"]
        _PROFILES[user]["email"] = email
        if not has_token and old_email != email:
            evidence.record(
                "profile_changed_without_csrf",
                module_id="csrf",
                path="/op/profile/update", method="POST",
                source_ip=request.remote_addr,
                via=via,
                severity="critical",
                extra={"user": user, "old_email": old_email, "new_email": email,
                       "backend": "operator"},
            )

    data = _PROFILES.get(user, _PROFILES["guest"])
    msg  = '<div class="success-msg">&#9989; Email updated successfully.</div>'
    return render_template_string(
        _PROFILE_PAGE,
        user=user, email=data["email"], role=data["role"], message=msg,
        user_initial=(user[0].upper() if user else "G"),
    )
