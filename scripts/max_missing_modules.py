#!/usr/bin/env python3
"""
max_missing_modules.py
Runs all 3 variants for dir_traversal and file_upload with full
attack flow, aiming for max scores on the skill radar.
"""
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


def req(url, method="GET", body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as ex:
        return 0, {"error": str(ex)}


def run_variant(module_id, variant_id):
    print(f"\n  [{module_id}/{variant_id}]")

    # Create
    s, b = req(f"{BASE}/api/sessions", "POST", {"module_id": module_id, "mode": "tutorial"})
    if s not in range(200, 300):
        print(f"    FAIL create: {s} {b}")
        return None
    sid = b["session_id"]

    # Set variant
    req(f"{BASE}/api/sessions/{sid}/variant", "POST", {"variant_id": variant_id})

    # Start (arms evidence window)
    req(f"{BASE}/api/sessions/{sid}/start", "POST")

    # Execute
    s, exec_b = req(f"{BASE}/api/sessions/{sid}/execute", "POST", timeout=90)
    state = exec_b.get("state", "?")
    result = exec_b.get("result") or {}
    summary = (result.get("summary") or "")[:80]
    print(f"    exec: {state}  {summary!r}")
    time.sleep(2)  # let target-agent events settle

    # Check progress
    s, prog = req(f"{BASE}/api/sessions/{sid}/check-progress", "POST")
    pct     = prog.get("progress_percent", 0)
    success = prog.get("success", False)
    done    = len(prog.get("completed_tasks", []))
    total   = len(prog.get("tasks", []))
    print(f"    progress: {pct}%  tasks={done}/{total}  success={success}")

    # If not fully succeeded, give it one more check after a short pause
    if not success and total > 0:
        time.sleep(2)
        s, prog2 = req(f"{BASE}/api/sessions/{sid}/check-progress", "POST")
        pct     = prog2.get("progress_percent", 0)
        success = prog2.get("success", False)
        done    = len(prog2.get("completed_tasks", []))
        print(f"    re-check: {pct}%  tasks={done}/{total}  success={success}")

    # Generate report (auto-update fires here via our main.py patch)
    s, report = req(f"{BASE}/api/sessions/{sid}/report", timeout=90)
    grade = report.get("grade", "?")
    score = report.get("score", "?")
    print(f"    report: grade={grade}  score={score}")

    # Also call explicit /skills/update as belt-and-suspenders fallback
    req(f"{BASE}/api/skills/update", "POST", {"session_id": sid})

    return {"module_id": module_id, "variant_id": variant_id,
            "grade": grade, "score": score}


def radar_row(module_id):
    _, data = req(f"{BASE}/api/skills")
    for m in data:
        if m["module_id"] == module_id:
            return m
    return {}


def main():
    targets = {
        "dir_traversal": ["plain", "encoded", "absolute"],
        "file_upload":   ["wrong_extension", "mime_spoof", "polyglot"],
    }

    print("=" * 60)
    print("  BEFORE")
    print("=" * 60)
    for mod in targets:
        row = radar_row(mod)
        print(f"  {mod:<16}  radar_score={row.get('score', 0):.1f}")

    results = []
    for module_id, variants in targets.items():
        print(f"\n{'='*60}")
        print(f"  {module_id.upper()}")
        print(f"{'='*60}")
        for vid in variants:
            r = run_variant(module_id, vid)
            if r:
                results.append(r)

    print(f"\n{'='*60}")
    print("  AFTER — Skill Radar")
    print(f"{'='*60}")
    _, radar = req(f"{BASE}/api/skills")
    all_pass = True
    for entry in radar:
        score = entry["score"]
        bar = "#" * int(score / 5) + "." * (20 - int(score / 5))
        print(f"  {entry['module_id']:<16} {bar}  {score:5.1f}")
        for v in entry["variants"]:
            marker = "OK" if v["best_score"] > 0 else "  "
            print(f"    [{marker}] {v['variant_id']:<22} score={v['best_score']:3d}  grade={v['best_grade'] or '-'}")
        if entry["module_id"] in targets and score == 0.0:
            all_pass = False

    print()
    if all_pass:
        print("  PASS — dir_traversal and file_upload now have real scores")
    else:
        print("  PARTIAL — some variants still at 0; check target-agent events")

    _, rec = req(f"{BASE}/api/skills/recommend")
    if rec.get("module_id"):
        print(f"\n  Next weakness: {rec['module_id']}/{rec.get('variant_id')} — {rec.get('reason','')}")


if __name__ == "__main__":
    main()
