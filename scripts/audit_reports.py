#!/usr/bin/env python3
"""
audit_reports.py
Fetches every cached session report and audits whether the Ollama grade
actually matches the attack evidence. Prints a per-session verdict.
"""
import json
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


def req(url, method="GET", body=None, timeout=30):
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


def grade_to_num(g):
    return {"S": 5, "A": 4, "B": 3, "C": 2, "F": 1}.get(str(g).upper(), 0)


def expected_grade(success, pct, ev_count):
    """
    Replicate report_agent._grade() logic for a sanity check.
      success -> +40
      task %  -> up to +40
      evidence (capped at 10) -> up to +20
    """
    score = 0.0
    if success:
        score += 40
    score += (pct / 100.0) * 40
    score += min(ev_count / 10.0, 1.0) * 20
    score = max(0, min(100, int(round(score))))
    if score >= 90 and success:
        return "S", score
    if score >= 75 and success:
        return "A", score
    if score >= 55 and success:
        return "B", score
    if score >= 30:
        return "C", score
    return "F", score


def main():
    _, sessions = req(f"{BASE}/api/sessions")
    if not isinstance(sessions, list):
        print("Could not fetch sessions:", sessions)
        return

    # Only sessions that have a cached report
    auditable = [s for s in sessions if s.get("learning_state") in ("completed", "idle")]

    print(f"{'='*72}")
    print(f"  REPORT AUDIT  —  {len(auditable)} sessions with reports")
    print(f"{'='*72}\n")

    mismatches = []

    for s in sorted(auditable, key=lambda x: x.get("created_at", 0)):
        sid        = s["session_id"]
        module_id  = s["module_id"]
        variant_id = s.get("variant_id") or "(none)"
        ls         = s.get("learning_state", "?")

        _, report = req(f"{BASE}/api/sessions/{sid}/report", timeout=60)
        if "error" in report:
            print(f"  [{sid[:10]}] {module_id}/{variant_id}  SKIP (no report: {report['error'][:60]})")
            continue

        # Reported values
        rep_grade   = report.get("grade", "?")
        rep_score   = int(report.get("score") or 0)
        rep_success = bool(report.get("success", False))
        ai_model    = report.get("ai_model", "?")
        ai_coaching = (report.get("ai_coaching") or "").strip()

        # Evidence quality indicators from the report
        tasks       = report.get("task_results", [])
        tasks_done  = sum(1 for t in tasks if t.get("complete"))
        tasks_total = len(tasks)
        pct         = int(report.get("progress_percent") or (
            round(tasks_done / tasks_total * 100) if tasks_total else 0))
        ev_timeline = report.get("evidence_timeline", [])
        ev_count    = len(ev_timeline)

        # What_you_did_right / what_you_missed
        rights  = report.get("what_you_did_right", [])
        missed  = report.get("what_you_missed", [])

        # Compute expected grade using same formula as report_agent
        exp_grade, exp_score = expected_grade(rep_success, pct, ev_count)

        # Check consistency
        grade_delta = grade_to_num(rep_grade) - grade_to_num(exp_grade)
        if abs(grade_delta) > 1:
            verdict = "MISMATCH"
            mismatches.append(sid)
        elif abs(grade_delta) == 1:
            verdict = "CLOSE"
        else:
            verdict = "OK"

        # Does coaching text actually reference relevant attack terms?
        attack_keywords = {
            "brute_force":   ["password", "credential", "login", "bruteforce", "brute"],
            "xss":           ["xss", "script", "injection", "payload", "reflect"],
            "csrf":          ["csrf", "forgery", "token", "state", "origin"],
            "cmd_injection": ["command", "injection", "shell", "rce", "exec"],
            "dir_traversal": ["traversal", "path", "directory", "../", "lfi"],
            "file_upload":   ["upload", "file", "extension", "mime", "polyglot"],
            "recon":         ["recon", "enumerat", "route", "endpoint", "discover"],
        }
        kws = attack_keywords.get(module_id, [])
        coaching_lower = ai_coaching.lower()
        keyword_hits = [k for k in kws if k in coaching_lower]
        coaching_relevant = len(keyword_hits) >= 1

        print(f"  {module_id:<16} {variant_id:<22}  {rep_grade}({rep_score:3d})  [{verdict}]")
        print(f"    model       : {ai_model}")
        print(f"    success     : {rep_success}  tasks={tasks_done}/{tasks_total}  evidence_events={ev_count}")
        print(f"    expected    : {exp_grade}({exp_score})  actual: {rep_grade}({rep_score})")
        print(f"    did_right   : {[r.get('title','?') for r in rights]}")
        print(f"    missed      : {[m.get('title','?') for m in missed]}")
        if ai_coaching:
            coaching_snippet = ai_coaching[:200].replace('\n', ' ')
            print(f"    ai_coaching : {coaching_snippet!r}")
            print(f"    kw_match    : {keyword_hits}  relevant={coaching_relevant}")
            if not coaching_relevant:
                print(f"    ** COACHING seems off-topic for {module_id}")
        else:
            print(f"    ai_coaching : (empty — rule-based fallback used)")
        print()

    print(f"{'='*72}")
    if mismatches:
        print(f"  MISMATCHES ({len(mismatches)}): {[s[:10] for s in mismatches]}")
    else:
        print(f"  All grades within 1 letter of formula-expected — no hard mismatches")
    print(f"{'='*72}")


if __name__ == "__main__":
    main()
