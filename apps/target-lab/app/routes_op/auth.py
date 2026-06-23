"""
routes_op/auth.py — Operator-mode HARDER login.

Same UI as routes/auth.py (the page renders identically) but the backend:
  * uses a different credential set that is NOT in the default rockyou-mini
    wordlist — `admin:password123` will fail here.
  * adds a 600ms delay per attempt to discourage trivial brute force.
  * returns a generic "Invalid credentials" message — no username enumeration.
  * still emits the same evidence event types (`login_failed`, `login_success`,
    `credential_found`) so the existing operator progress ladder applies
    without changes to lab_progress.py.

The lab_url() helper inherits X-Forwarded-Prefix from the request so form
actions resolve back to /target-op/auth/login when reached via the iframe,
and to /op/auth/login when reached directly via the AttackBox.
"""
import json
import logging
import time

from flask import Blueprint, request, render_template_string, session, redirect, current_app

logger = logging.getLogger("target.auth_op")

auth_op_bp = Blueprint("auth_op", __name__)

# Harder cred set — not in default rockyou-mini.
# Learners need to either run a longer wordlist, hand-craft against the policy
# hint shown on the login page, or chain hydra with a bigger dictionary.
_USERS = {
    "admin":    "Br3akMe!2025",
    "operator": "Tr0ub4dor&3",
    "service":  "S3rvice@cct",
}

# Per-attempt delay (seconds). Slow but does not block — a hint that this
# backend has minimal protections, not a hard lockout.
_ATTEMPT_DELAY_SEC = 0.6

# Reuse the guided-mode template by string-importing it. The page looks
# identical to /target/auth/login but the form posts to lab_url('/auth/login')
# which, with X-Forwarded-Prefix=/target-op, becomes /target-op/auth/login.
from routes.auth import _LOGIN_PAGE  # noqa: E402


@auth_op_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(_LOGIN_PAGE, username="", error="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Slow every attempt — brute force still possible, just costlier.
    time.sleep(_ATTEMPT_DELAY_SEC)

    import evidence
    via = current_app.detect_via()

    if _USERS.get(username) == password:
        session["user"] = username
        logger.info(json.dumps({
            "event":     "login_success",
            "endpoint":  "/op/auth/login",
            "username":  username,
            "source_ip": request.remote_addr,
        }))
        evidence.record(
            "login_success",
            module_id="brute_force",
            path="/op/auth/login", method="POST",
            source_ip=request.remote_addr,
            via=via,
            extra={"username": username, "backend": "operator"},
        )
        evidence.record(
            "credential_found",
            module_id="brute_force",
            path="/op/auth/login", method="POST",
            source_ip=request.remote_addr,
            via=via,
            severity="high",
            learner_message=(
                f"Valid credential confirmed against the harder operator "
                f"backend: {username} / (correct password)."
            ),
            extra={"username": username, "backend": "operator"},
        )
        return redirect(current_app.lab_url("/profile/"))

    # Generic error — no username enumeration on the harder backend.
    msg = '<div class="error-msg">Invalid credentials</div>'
    logger.warning(json.dumps({
        "event":     "login_failure",
        "endpoint":  "/op/auth/login",
        "username":  username,
        "source_ip": request.remote_addr,
    }))
    evidence.record(
        "login_failed",
        module_id="brute_force",
        path="/op/auth/login", method="POST",
        source_ip=request.remote_addr,
        via=via,
        extra={
            "username":  username,
            "known_user": False,            # operator backend hides this
            "backend":   "operator",
        },
    )
    return render_template_string(_LOGIN_PAGE, username=username, error=msg), 401


@auth_op_bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(current_app.lab_url("/"))
