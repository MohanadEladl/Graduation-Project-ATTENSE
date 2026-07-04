#!/usr/bin/env python3
"""
verify_auto_update.py
Proves that skill_store.update() fires automatically inside get_report(),
with NO explicit call to POST /api/skills/update.
"""
import json
import sys
import time
import urllib.request

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
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return json.loads(raw)
        except Exception:
            return {"error": raw}
    except Exception as ex:
        return {"error": str(ex)}


def variant_score(module_id, variant_id):
    radar = req(BASE + "/api/skills")
    for m in radar:
        if m["module_id"] == module_id:
            for v in m["variants"]:
                if v["variant_id"] == variant_id:
                    return v["best_score"], v["best_grade"], v["attempts"]
    return 0, None, 0


# Use xss/alternate_context — already at 0 from fresh start
MODULE  = "xss"
VARIANT = "alternate_context"

score_before, _, attempts_before = variant_score(MODULE, VARIANT)
print(f"BEFORE: {MODULE}/{VARIANT}  best_score={score_before}  attempts={attempts_before}")

# Full flow — NO /api/skills/update call
sess   = req(BASE + "/api/sessions",                "POST", {"module_id": MODULE, "mode": "tutorial"})
sid    = sess["session_id"]
req(BASE + f"/api/sessions/{sid}/variant",          "POST", {"variant_id": VARIANT})
req(BASE + f"/api/sessions/{sid}/start",            "POST")
exec_r = req(BASE + f"/api/sessions/{sid}/execute", "POST")
print(f"execute: state={exec_r.get('state','?')}")
time.sleep(1.5)
prog   = req(BASE + f"/api/sessions/{sid}/check-progress", "POST")
print(f"progress: {prog.get('progress_percent')}%  success={prog.get('success')}")
report = req(BASE + f"/api/sessions/{sid}/report")      # <-- auto-update fires HERE
print(f"report: grade={report.get('grade')}  score={report.get('score')}")

time.sleep(0.5)
score_after, grade_after, attempts_after = variant_score(MODULE, VARIANT)
print(f"AFTER:  {MODULE}/{VARIANT}  best_score={score_after}  attempts={attempts_after}  grade={grade_after}")

if score_after > score_before or attempts_after > attempts_before:
    print("\n  AUTO-UPDATE OK — skill store updated automatically via get_report()")
    sys.exit(0)
else:
    print("\n  AUTO-UPDATE FAILED — skill store was NOT updated (old container code?)")
    sys.exit(1)
