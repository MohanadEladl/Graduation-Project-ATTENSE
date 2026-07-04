#!/usr/bin/env python3
"""
verify_grade_fix.py
Runs one Easy, one Medium, and one Hard variant fresh and prints the
resulting grade, score, Ollama coaching, and a match verdict.
"""
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8000"

TEST_CASES = [
    # (module, variant, expected_difficulty, expect_ollama)
    ("recon",         "manual",        "Easy",   True),
    ("dir_traversal", "encoded",       "Medium",  True),
    ("brute_force",   "hydra_targeted","Hard",    True),
    ("xss",           "stored_attempt","Hard",    True),
    ("file_upload",   "polyglot",      "Hard",    True),
]


def req(url, method="GET", body=None, timeout=90):
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


def run_and_report(module_id, variant_id, expected_diff, expect_ollama):
    print(f"\n{'─'*66}")
    print(f"  {module_id}/{variant_id}  [{expected_diff}]")
    print(f"{'─'*66}")

    # Create + configure
    _, sess = req(f"{BASE}/api/sessions", "POST", {"module_id": module_id, "mode": "tutorial"})
    sid = sess["session_id"]
    req(f"{BASE}/api/sessions/{sid}/variant", "POST", {"variant_id": variant_id})
    req(f"{BASE}/api/sessions/{sid}/start",   "POST")

    # Execute
    _, exec_b = req(f"{BASE}/api/sessions/{sid}/execute", "POST")
    state   = exec_b.get("state", "?")
    result  = exec_b.get("result") or {}
    summary = (result.get("summary") or "")[:80]
    print(f"  exec      : state={state}  summary={summary!r}")
    time.sleep(2)

    # Progress
    _, prog = req(f"{BASE}/api/sessions/{sid}/check-progress", "POST")
    pct     = prog.get("progress_percent", 0)
    success = prog.get("success", False)
    diff    = prog.get("variant_difficulty", "?")
    tasks   = prog.get("tasks", [])
    done    = len([t for t in tasks if t.get("complete")])
    print(f"  progress  : {pct}%  success={success}  difficulty={diff}  tasks={done}/{len(tasks)}")

    # Report (Ollama fires here)
    _, report = req(f"{BASE}/api/sessions/{sid}/report", timeout=120)
    grade    = report.get("grade", "?")
    score    = report.get("score", "?")
    ai_model = report.get("ai_model", "?")
    coaching = (report.get("ai_coaching") or "").strip()

    print(f"  grade     : {grade}  score={score}")
    print(f"  ai_model  : {ai_model}")

    # Print coaching with wrapping
    if coaching:
        print(f"  coaching  :")
        for line in coaching.split("\n"):
            while len(line) > 78:
                print(f"    {line[:78]}")
                line = line[78:]
            if line.strip():
                print(f"    {line}")
    else:
        print(f"  coaching  : (empty)")

    # Verdict
    used_ollama = "ollama" in ai_model.lower()
    diff_match  = diff.lower() == expected_diff.lower() if diff != "?" else False
    grade_ok    = grade in ("S", "A", "B", "C") if success else grade == "F"

    issues = []
    if expect_ollama and not used_ollama:
        issues.append("Ollama not used (rule-based fallback)")
    if not diff_match:
        issues.append(f"difficulty={diff!r} expected={expected_diff!r}")
    if not grade_ok:
        issues.append(f"grade={grade} looks wrong for success={success}")

    print(f"\n  {'PASS' if not issues else 'ISSUES'}: {', '.join(issues) if issues else 'grade and coaching look correct'}")
    return not issues


def main():
    print("=" * 66)
    print("  GRADE + COACHING VERIFICATION")
    print("=" * 66)

    results = []
    for tc in TEST_CASES:
        ok = run_and_report(*tc)
        results.append(ok)

    print(f"\n{'='*66}")
    passed = sum(results)
    print(f"  {passed}/{len(results)} test cases passed")
    if passed < len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
