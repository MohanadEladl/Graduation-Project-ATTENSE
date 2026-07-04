#!/usr/bin/env python3
"""
test_skill_radar.py — Runs a mixed set of attacks to verify the Skill Radar
graph is wired to real data.

Attack profile (intentionally varied, not 100% successful across the board):
  HIGH  score expected  : recon, csrf, xss (execute + evidence collection)
  MED   score expected  : brute_force, cmd_injection (execute, harder variant)
  LOW   score expected  : dir_traversal, file_upload (no execute — tests zero leg)

Run inside the backend container:
  docker exec attense_red_team_backend python3 /scripts/test_skill_radar.py
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


# ── helpers ─────────────────────────────────────────────────────────────────

def req(url: str, method: str = "GET", body=None, timeout: int = 30):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode(errors="replace")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        return e.code, json.loads(raw) if raw.strip() else {}
    except Exception as ex:
        return 0, {"error": str(ex)}


def ok(status: int) -> bool:
    return 200 <= status < 300


def banner(msg: str) -> None:
    print(f"\n{'─'*60}\n  {msg}\n{'─'*60}")


# ── attack runner ────────────────────────────────────────────────────────────

def run_attack(
    module_id: str,
    variant_id: str,
    *,
    do_start: bool = True,
    do_execute: bool = True,
    do_progress: bool = True,
    label: str = "",
    expected_tier: str = "?",
) -> dict:
    tag = label or f"{module_id}/{variant_id}"
    print(f"\n[{expected_tier}] {tag}")

    # 1. Create session
    status, body = req(f"{BASE}/api/sessions", "POST",
                       {"module_id": module_id, "mode": "tutorial"})
    if not ok(status):
        print(f"  FAIL create: {status} {body}")
        return {}
    sid = body["session_id"]
    print(f"  session: {sid[:12]}…")

    # 2. Set variant
    status, _ = req(f"{BASE}/api/sessions/{sid}/variant", "POST",
                    {"variant_id": variant_id})
    if not ok(status):
        print(f"  WARN set variant: {status}")

    # 3. Start (arm mission timer + evidence window)
    if do_start:
        status, _ = req(f"{BASE}/api/sessions/{sid}/start", "POST")
        if not ok(status):
            print(f"  WARN start: {status}")
        else:
            print("  started")

    # 4. Execute the attack module
    if do_execute:
        print("  executing attack…")
        status, exec_body = req(f"{BASE}/api/sessions/{sid}/execute", "POST",
                                timeout=60)
        if ok(status):
            state = exec_body.get("state", "?")
            result = exec_body.get("result") or {}
            summary = (result.get("summary") or "")[:80]
            print(f"  exec state={state}  summary={summary!r}")
        else:
            print(f"  WARN execute: {status} {exec_body}")
        # Brief pause so target-agent events propagate
        time.sleep(1.5)

    # 5. Check progress (maps evidence events to task ladder)
    if do_progress:
        status, prog = req(f"{BASE}/api/sessions/{sid}/check-progress", "POST")
        if ok(status):
            pct = prog.get("progress_percent", 0)
            success = prog.get("success", False)
            tasks_done = len(prog.get("completed_tasks", []))
            tasks_total = len(prog.get("tasks", []))
            print(f"  progress: {pct}%  tasks={tasks_done}/{tasks_total}  success={success}")
        else:
            print(f"  WARN progress: {status}")

    # 6. Generate report (auto-updates skill store via our main.py fix;
    #    also call /skills/update explicitly for containers on the old build)
    print("  generating report…")
    status, report = req(f"{BASE}/api/sessions/{sid}/report", "GET", timeout=60)
    if ok(status):
        grade = report.get("grade", "?")
        score = report.get("score", "?")
        print(f"  report grade={grade}  score={score}")
    else:
        print(f"  WARN report: {status} {str(report)[:120]}")

    # 7. Explicit skill store update (needed on containers without the auto-update patch)
    status2, upd = req(f"{BASE}/api/skills/update", "POST", {"session_id": sid})
    if ok(status2):
        print(f"  skill store updated")
    else:
        # 409 = no report cache (score 0 or report failed); still valid
        print(f"  skill update: {status2}")

    return {"sid": sid, "module_id": module_id, "variant_id": variant_id}


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    banner("Pre-attack skill radar")
    _, radar_before = req(f"{BASE}/api/skills")
    for entry in radar_before:
        print(f"  {entry['module_id']:<16}  score={entry['score']:.1f}")

    # ── HIGH tier: full flow (start + execute + check-progress + report)
    # These attack modules generate the exact event types their easy variant needs.
    banner("HIGH tier attacks (full flow)")
    run_attack("recon",         "wordlist",       expected_tier="HIGH",
               label="recon/wordlist — automated enumeration")
    run_attack("csrf",          "basic_forgery",  expected_tier="HIGH",
               label="csrf/basic_forgery — forged POST")
    run_attack("xss",           "reflected",      expected_tier="HIGH",
               label="xss/reflected — script injection")

    # ── MEDIUM tier: execute runs but variant expects harder technique patterns
    # The automated attack won't satisfy all tasks, giving partial scores.
    banner("MEDIUM tier attacks (execute + harder variant)")
    run_attack("brute_force",   "hydra_targeted", expected_tier="MED",
               label="brute_force/hydra_targeted — expects hydra patterns")
    run_attack("cmd_injection", "subshell",       expected_tier="MED",
               label="cmd_injection/subshell — expects $() substitution patterns")

    # ── LOW tier: no execute → 0 evidence → score will be very low
    # Tests that the graph correctly shows weak areas (not just default zeros).
    banner("LOW tier attacks (no execute — simulates skipped/abandoned mission)")
    run_attack("dir_traversal", "encoded",    expected_tier="LOW",
               do_execute=False,
               label="dir_traversal/encoded — no execute")
    run_attack("file_upload",   "polyglot",   expected_tier="LOW",
               do_execute=False,
               label="file_upload/polyglot — no execute")

    # ── Final radar snapshot
    banner("Post-attack skill radar")
    time.sleep(1)
    _, radar_after = req(f"{BASE}/api/skills")
    all_zero = True
    for entry in radar_after:
        mid   = entry["module_id"]
        score = entry["score"]
        if score > 0:
            all_zero = False
        bar = "█" * int(score / 5) + "·" * (20 - int(score / 5))
        print(f"  {mid:<16}  {bar}  {score:5.1f}")
    print()
    if all_zero:
        print("  ✗  FAIL — radar still all zeros; check skill_store auto-update wiring")
        sys.exit(1)
    else:
        print("  ✓  PASS — radar has real data; graph is live and reflects attack outcomes")

    # ── Recommendation check
    _, rec = req(f"{BASE}/api/skills/recommend")
    if rec and rec.get("module_id"):
        print(f"\n  Weakest area: {rec['module_id']}/{rec.get('variant_id')} — {rec.get('reason','')}")


if __name__ == "__main__":
    main()
