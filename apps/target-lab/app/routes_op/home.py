"""
routes_op/home.py — Operator-mode HARDER recon surface.

Same UI templates (the portal index, security.txt, etc) but:
  * /op/robots.txt returns 404 (the easy clue is gone).
  * /op/.well-known/security.txt returns 404.
  * The hidden clue is moved to /.git/config — a more realistic recon
    target the learner has to guess at or enumerate with gobuster.
  * /op/evil/csrf-demo still serves the same lure page so the CSRF
    module's third task is reachable.

Same evidence event types so lab_progress.py is unchanged.
"""
import json
import logging
from flask import Blueprint, current_app, redirect, render_template_string, request, Response

logger = logging.getLogger("target.home_op")
home_op_bp = Blueprint("home_op", __name__)

# Reuse the guided-mode templates verbatim — UI must look identical.
from routes.home import _INDEX, _LURE_PAGE  # noqa: E402


@home_op_bp.route("/")
def index():
    import evidence
    logger.info(json.dumps({
        "event":     "portal_visited",
        "endpoint":  "/op/",
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
    }))
    evidence.record(
        "portal_visited",
        module_id="recon",
        path="/op/", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        extra={"backend": "operator"},
    )
    return render_template_string(_INDEX)


# ── Aliases (preserve canonical /op/* paths) ────────────────────────────────
@home_op_bp.route("/tools/ping")
def alias_ping():
    qs = request.query_string.decode("utf-8", errors="replace")
    target = current_app.lab_url("/system/ping")
    if qs:
        target += f"?{qs}"
    return redirect(target, code=307)


@home_op_bp.route("/upload", methods=["GET", "POST"])
def alias_upload():
    return redirect(current_app.lab_url("/files/upload"), code=307)


@home_op_bp.route("/files/view")
def alias_files_view():
    qs = request.query_string.decode("utf-8", errors="replace")
    target = current_app.lab_url("/files/read")
    if qs:
        target += f"?{qs}"
    return redirect(target, code=307)


# ── Hidden clue — HARDER ────────────────────────────────────────────────────
# /op/robots.txt and /op/.well-known/security.txt are intentionally 404 in
# operator mode — the obvious clues are gone. The real clue is now at
# /.git/config which a learner has to enumerate with gobuster or guess at.
@home_op_bp.route("/robots.txt")
def robots_txt():
    return Response("", status=404, mimetype="text/plain")


@home_op_bp.route("/.well-known/security.txt")
def security_txt():
    return Response("", status=404, mimetype="text/plain")


@home_op_bp.route("/.git/config")
def git_config():
    """Realistic operator-grade recon target — exposed .git/config."""
    import evidence
    evidence.record(
        "hidden_clue_accessed",
        module_id="recon",
        path="/op/.git/config", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        severity="medium",
        learner_message="Discovered exposed .git/config — internal repository metadata leaked.",
        extra={"backend": "operator"},
    )
    return Response(
        "[core]\n"
        "    repositoryformatversion = 0\n"
        "    filemode = false\n"
        "    bare = false\n"
        "[remote \"origin\"]\n"
        "    url = git@gitlab.acme.local:internal/staff-portal.git\n"
        "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "    remote = origin\n"
        "    merge = refs/heads/main\n",
        mimetype="text/plain",
    )


# ── CSRF lure (still served at /op/evil/csrf-demo) ──────────────────────────
@home_op_bp.route("/evil/csrf-demo")
def csrf_lure():
    import evidence
    evidence.record(
        "csrf_lure_visited",
        module_id="csrf",
        path="/op/evil/csrf-demo", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        severity="medium",
        extra={"backend": "operator"},
    )
    return render_template_string(_LURE_PAGE)
