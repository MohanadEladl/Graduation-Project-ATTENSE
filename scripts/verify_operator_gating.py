"""
verify_operator_gating.py — End-to-end proof that operator mode requires
AttackBox traffic and rejects browser-iframe activity.

What it does
------------
1.  Boots the target-agent Flask app in-process via the test client. No
    Docker required — every vulnerable route runs and records evidence into
    the same in-memory store the production container uses.
2.  Patches `backend.lab_progress.fetch_events` so that instead of HTTP-
    fetching from the target-agent container, it reads directly from the
    in-process `evidence` store. This is the same data the real HTTP
    endpoint serves, just without the network hop.
3.  Drives two end-to-end scenarios for the `brute_force` module:
       Scenario A — browser-only:
         8 failed logins + 1 successful login, all sent with
         `X-Forwarded-Prefix: /target` (lab-browser proxy header).
         Expected:
           * guided-mode progress > 0
           * operator-mode progress == 0    (browser activity is excluded)
       Scenario B — attackbox-only:
         8 failed logins + 1 successful login, all sent with
         `User-Agent: AttenseAttackBox/1.0`.
         Expected:
           * operator-mode progress == 100
           * all 4 operator tasks complete

Run:
    python scripts/verify_operator_gating.py
"""
from __future__ import annotations

import sys
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Make target-agent app importable (so `import evidence`, `from routes.auth ...` work)
sys.path.insert(0, str(ROOT / "target-agent" / "app"))
# Make red-team backend importable (`from backend import lab_progress`)
sys.path.insert(0, str(ROOT / "red-team"))


# ── Build a minimal Flask app with just the routes we need ──────────────────
# We can't simply `import main` because target-agent/app/main.py registers
# routes/files.py which performs disk I/O at import time on /app/static —
# a Linux-only path that doesn't exist on the verifier host. So we replicate
# only the parts we actually exercise: auth_bp + detect_via.
import socket as _socket
from flask import Flask, request

# Create the bare minimum filesystem layout that the imported modules expect,
# under a temp dir, in case any module does path resolution at import time.
_TMP = Path(tempfile.mkdtemp(prefix="attense_verify_"))
(_TMP / "logs").mkdir(parents=True, exist_ok=True)

import evidence as target_evidence   # noqa: E402  (in-process evidence store)
from routes.auth import auth_bp      # noqa: E402  (brute_force endpoint)

app = Flask(__name__)
app.secret_key = "lab-secret-123"


# Replicate detect_via() from target-agent/app/main.py exactly. This is the
# header-classification logic the real container runs.
_ATTACKBOX_IPS: set[str] = set()


def _refresh_attackbox_ips() -> None:
    for host in ("attackbox", "attense_attackbox"):
        try:
            for info in _socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip:
                    _ATTACKBOX_IPS.add(ip)
        except OSError:
            pass


_refresh_attackbox_ips()


def detect_via() -> str:
    try:
        ua = (request.headers.get("User-Agent") or "")
        prefix = (request.headers.get("X-Forwarded-Prefix") or "").rstrip("/")
        ip = request.remote_addr or ""
        if "AttenseAttackBox" in ua:
            return "attackbox"
        if not _ATTACKBOX_IPS:
            _refresh_attackbox_ips()
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


app.register_blueprint(auth_bp, url_prefix="/auth")


from backend import lab_progress     # noqa: E402


# ── Patch lab_progress.fetch_events to read from in-process evidence ────────
def _local_fetch_events(since=0.0, module_id=None, limit=500):
    return target_evidence.list_events(
        since=since, module_id=module_id, limit=limit,
    )

lab_progress.fetch_events = _local_fetch_events


# ── Helpers ────────────────────────────────────────────────────────────────
def _hr(label):
    bar = "-" * (60 - len(label))
    print(f"\n-- {label} {bar}")


def _post_login(client, username, password, *, via_kind):
    """Send a POST /auth/login with headers that mimic the channel."""
    headers = {}
    if via_kind == "browser":
        # The lab-browser proxy always sets this prefix.
        headers["X-Forwarded-Prefix"] = "/target"
        # A normal browser user-agent
        headers["User-Agent"] = "Mozilla/5.0 (verifier; lab-browser)"
    elif via_kind == "attackbox":
        # The AttackBox container's /etc/curlrc + aliases stamp this UA.
        headers["User-Agent"] = "AttenseAttackBox/1.0"
    else:
        raise ValueError(via_kind)
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        headers=headers,
    )


def _drive_scenario(via_kind):
    """Run 8 failed + 1 successful login via the named channel."""
    client = app.test_client()
    target_evidence.reset()  # fresh evidence store

    # 8 failed logins (well above the brute_force_pattern threshold of 3)
    for i in range(8):
        _post_login(client, "admin", f"wrongpass{i}", via_kind=via_kind)

    # 1 successful login (planted credential admin:password123)
    r = _post_login(client, "admin", "password123", via_kind=via_kind)
    assert r.status_code in (200, 302), (
        f"login attempt unexpectedly returned {r.status_code} for {via_kind}"
    )


def _print_progress(label, mode, started_at):
    p = lab_progress.compute("brute_force", mission_started_at=started_at, mode=mode)
    print(f"  [{label}/{mode}]  progress = {p['progress_percent']:>3}%   "
          f"success = {p['success']}   "
          f"events_examined = {p['events_examined']}")
    for i, t in enumerate(p["tasks"]):
        check = "OK" if t["complete"] else " "
        print(f"      {check} task {i+1}: "
              f"{t['title']:<55s}  matched={t['match_count']}/{t['min_count']}")
    return p


# ── Main verification ───────────────────────────────────────────────────────
def main():
    print("ATTENSE — operator-mode evidence-gating verification")
    print(f"target-agent app: {ROOT / 'target-agent' / 'app'}")
    print(f"red-team backend: {ROOT / 'red-team'}")

    started_at = time.time() - 1.0  # one second back so we capture all events

    _hr("Scenario A: browser-only (X-Forwarded-Prefix: /target)")
    _drive_scenario("browser")
    # Snapshot the via distribution
    all_evs = target_evidence.list_events()
    via_counts = {}
    for e in all_evs:
        via_counts[e["via"]] = via_counts.get(e["via"], 0) + 1
    print(f"  recorded {len(all_evs)} evidence events; via distribution = {via_counts}")
    a_guided = _print_progress("A", "guided",   started_at)
    a_op     = _print_progress("A", "operator", started_at)

    _hr("Scenario B: attackbox-only (User-Agent: AttenseAttackBox/1.0)")
    _drive_scenario("attackbox")
    all_evs = target_evidence.list_events()
    via_counts = {}
    for e in all_evs:
        via_counts[e["via"]] = via_counts.get(e["via"], 0) + 1
    print(f"  recorded {len(all_evs)} evidence events; via distribution = {via_counts}")
    b_guided = _print_progress("B", "guided",   started_at)
    b_op     = _print_progress("B", "operator", started_at)

    # ── Assertions ─────────────────────────────────────────────────────────
    _hr("Assertions")
    failures = []

    if a_guided["progress_percent"] <= 0:
        failures.append("A/guided should be > 0%")
    else:
        print(f"  ✓ A/guided > 0%   ({a_guided['progress_percent']}%)")

    if a_op["progress_percent"] != 0:
        failures.append(
            f"A/operator should be 0% (browser activity must NOT count); "
            f"got {a_op['progress_percent']}%"
        )
    else:
        print(f"  ✓ A/operator == 0%   (browser activity correctly excluded)")

    if b_op["progress_percent"] != 100:
        failures.append(
            f"B/operator should be 100% (attackbox activity should drive ladder); "
            f"got {b_op['progress_percent']}%"
        )
    else:
        print(f"  ✓ B/operator == 100% (all operator tasks complete)")

    if not b_op["success"]:
        failures.append("B/operator should report success=True")
    else:
        print(f"  ✓ B/operator success == True")

    print()
    if failures:
        print("RESULT: FAIL")
        for f in failures:
            print(f"  X {f}")
        sys.exit(1)
    print("RESULT: PASS — operator mode is correctly gated to AttackBox traffic.")


if __name__ == "__main__":
    main()
