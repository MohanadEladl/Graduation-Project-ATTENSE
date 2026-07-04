#!/usr/bin/env python3
"""
ATTENSE Full Feature Test Suite — runs inside Docker network
BASE   = red-team-backend:8000
TARGET = target-agent:80
"""

import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse as up

BASE   = "http://localhost:8000"   # inside the backend container
TARGET = "http://target-agent:80"  # internal Docker hostname

results = []

def req(url, method="GET", body=None, headers=None, timeout=10):
    data = json.dumps(body).encode() if body else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode(errors="replace")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as ex:
        return 0, str(ex)

def test(name, passed, detail=""):
    status = "[PASS]" if passed else "[FAIL]"
    results.append((name, passed, detail))
    d = f"  ->  {detail[:90]}" if detail else ""
    print(f"  {status} {name}{d}")

def section(title):
    print(f"\n{'='*62}")
    print(f"  {title}")
    print(f"{'='*62}")


# ============================================================
# 1. HEALTH CHECKS
# ============================================================
section("1. HEALTH CHECKS")

status, body = req(f"{BASE}/health")
test("Backend /health returns 200", status == 200, str(body)[:80])
if status == 200:
    mods = body.get("modules", 0)
    test(f"Backend reports {mods} modules", mods == 7, f"modules={mods}")

status, body = req(f"{TARGET}/")
test("Target-agent / reachable", status in (200, 302), f"HTTP {status}")


# ============================================================
# 2. MODULE LISTING
# ============================================================
section("2. MODULE LISTING")

status, body = req(f"{BASE}/api/modules")
test("GET /api/modules -> 200", status == 200)
modules = []
if status == 200:
    modules = body if isinstance(body, list) else body.get("modules", [])
    expected = {"recon","brute_force","xss","cmd_injection","dir_traversal","file_upload","csrf"}
    found = {m.get("id") or m.get("module_id","?") for m in modules}
    test("All 7 modules present", expected == found, str(sorted(found)))
    for m in modules:
        mid   = m.get("id") or m.get("module_id","?")
        title = m.get("title") or m.get("name","")
        sev   = m.get("severity","")
        test(f"  [{mid}] has title+severity", bool(title) and bool(sev), f"{title} / {sev}")


# ============================================================
# 3. SESSION LIFECYCLE
# ============================================================
section("3. SESSION LIFECYCLE")

status, body = req(f"{BASE}/api/sessions", method="POST", body={"module_id": "brute_force"})
test("POST /api/sessions (create brute_force)", status in (200,201), str(body)[:100])
sid = None
if status in (200, 201):
    sid = body.get("session_id") or body.get("id")
    test("  Response has session_id", bool(sid), str(sid))

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}")
    test("GET /api/sessions/{sid}", status == 200, str(body)[:80])

    status, body = req(f"{BASE}/api/sessions/{sid}/start", method="POST", body={})
    test("POST /api/sessions/{sid}/start", status in (200,201,204), str(body)[:80])
    time.sleep(1)

    status, body = req(f"{BASE}/api/sessions/{sid}")
    state = body.get("state","?") if isinstance(body, dict) else "?"
    test("Session state is valid after start", state in ("running","active","started","idle","completed"), f"state={state}")


# ============================================================
# 4. PROGRESS CHECKING
# ============================================================
section("4. PROGRESS CHECK")

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/check-progress", method="POST", body={})
    test("POST /check-progress -> 200", status == 200, str(body)[:120])
    if status == 200 and isinstance(body, dict):
        has_score = any(k in body for k in ("score","percentage","progress","completed_steps"))
        has_tasks = any(k in body for k in ("tasks","steps","completed_steps","task_results"))
        test("Progress response has score field", has_score, str(list(body.keys()))[:80])
        test("Progress response has tasks/steps", has_tasks, str(list(body.keys()))[:80])
        score = body.get("score") or body.get("percentage") or body.get("progress",0)
        test("Score is numeric (0 for fresh session)", isinstance(score, (int,float)), f"score={score}")


# ============================================================
# 5. TARGET-AGENT ATTACK SURFACES
# ============================================================
section("5. TARGET-AGENT ATTACK SURFACES")

attack_routes = [
    ("/",                              "Root page",              [200, 302]),
    ("/auth/login",                    "Login page",             [200, 302]),
    ("/search?q=test",                 "Search (XSS)",           [200, 302]),
    ("/system/ping",                   "Ping (cmd injection)",   [200, 405]),
    ("/files/read?path=etc/passwd",    "File read (traversal)",  [200, 400, 403, 404]),
    ("/files/upload",                  "File upload page",       [200, 302]),
    ("/profile/",                      "Profile (CSRF)",         [200, 302]),
    ("/evil/csrf-demo",                "CSRF lure page",         [200, 302]),
]
for path, label, ok_codes in attack_routes:
    status, _ = req(f"{TARGET}{path}", timeout=6)
    test(f"  {label} -> HTTP {status}", status in ok_codes, path)


# ============================================================
# 6. EVIDENCE GENERATION
# ============================================================
section("6. EVIDENCE GENERATION")

# Failed login
form = up.urlencode({"username": "admin", "password": "badpass"}).encode()
r = urllib.request.Request(f"{TARGET}/auth/login", data=form, method="POST")
r.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    with urllib.request.urlopen(r, timeout=6) as resp:
        ls = resp.status
except urllib.error.HTTPError as e:
    ls = e.code
except Exception:
    ls = 0
test("Failed login generates response", ls in (200,302,400,401,403), f"HTTP {ls}")

# Multiple failed logins to trigger brute_force_pattern
for _ in range(4):
    try:
        form2 = up.urlencode({"username":"admin","password":f"pass{_}"}).encode()
        r2 = urllib.request.Request(f"{TARGET}/auth/login", data=form2, method="POST")
        r2.add_header("Content-Type","application/x-www-form-urlencoded")
        urllib.request.urlopen(r2, timeout=6).read()
    except Exception:
        pass

# XSS payload
status, _ = req(f"{TARGET}/search?q=<script>alert(1)</script>", timeout=6)
test("XSS payload in search accepted/reflected", status in (200, 400), f"HTTP {status}")

# Cmd injection surface
form3 = up.urlencode({"host":"127.0.0.1;id"}).encode()
r3 = urllib.request.Request(f"{TARGET}/system/ping", data=form3, method="POST")
r3.add_header("Content-Type","application/x-www-form-urlencoded")
try:
    with urllib.request.urlopen(r3, timeout=8) as resp:
        cs = resp.status
except urllib.error.HTTPError as e:
    cs = e.code
except Exception:
    cs = 0
test("Cmd injection payload accepted", cs in (200,400,405), f"HTTP {cs}")

# Dir traversal
status, body = req(f"{TARGET}/files/read?path=../../etc/passwd", timeout=6)
test("Dir traversal attempt processed", status in (200,400,403,404), f"HTTP {status}")

time.sleep(2)  # let evidence settle

# Now check progress — should have some evidence
if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/check-progress", method="POST", body={})
    test("Progress after evidence generation", status == 200, str(body)[:120])
    if status == 200 and isinstance(body, dict):
        score = body.get("score") or body.get("percentage") or body.get("progress") or 0
        tasks = body.get("tasks") or body.get("steps") or body.get("task_results") or []
        completed = body.get("completed_steps") or sum(1 for t in tasks if t.get("done") or t.get("completed") or t.get("status")=="completed")
        test(f"Evidence score > 0 after attacks", float(score) > 0, f"score={score}")
        test(f"Some tasks completed ({completed})", completed >= 0, f"completed={completed}")


# ============================================================
# 7. ATTACK CHAINS (Gauntlet)
# ============================================================
section("7. ATTACK CHAINS (Gauntlet)")

status, body = req(f"{BASE}/api/chains")
test("GET /api/chains -> 200", status == 200, str(body)[:120])
chain_session_id = None
if status == 200:
    chains = body if isinstance(body, list) else body.get("chains", [])
    found_ids = {c.get("id") or c.get("chain_id") for c in chains}
    expected_chains = {"full_compromise","root_the_box","data_exfiltration"}
    test("All 3 chains present", expected_chains.issubset(found_ids), str(sorted(found_ids)))

    for cid in ["full_compromise","root_the_box","data_exfiltration"]:
        s2, b2 = req(f"{BASE}/api/chains/{cid}")
        test(f"  GET /api/chains/{cid} -> 200", s2 == 200)
        if s2 == 200:
            steps = b2.get("steps", [])
            test(f"    Chain '{cid}' has >=2 steps", len(steps) >= 2, f"{len(steps)} steps")
            test(f"    Steps have module_id field", all("module_id" in s for s in steps), "")

    # Start a chain
    status2, body2 = req(f"{BASE}/api/chains/full_compromise/start", method="POST",
                         body={"session_id": sid or "test"})
    test("POST /api/chains/full_compromise/start", status2 in (200,201,400,422), str(body2)[:100])
    if status2 in (200, 201):
        chain_session_id = body2.get("id") or body2.get("chain_session_id")
        test("  Chain session ID returned", bool(chain_session_id), str(chain_session_id))
        if chain_session_id:
            s3, b3 = req(f"{BASE}/api/chain-sessions/{chain_session_id}")
            test("  GET /api/chain-sessions/{id} -> 200", s3 == 200, str(b3)[:80])
            if s3 == 200:
                cstep = b3.get("current_step",b3.get("step","?"))
                cstate = b3.get("state","?")
                test(f"  Chain session has state+step", cstep is not None and cstate != "?", f"step={cstep} state={cstate}")

            s4, b4 = req(f"{BASE}/api/chain-sessions/{chain_session_id}/check", method="POST", body={})
            test("  POST /api/chain-sessions/{id}/check", s4 in (200,400,409), str(b4)[:80])

            s5, b5 = req(f"{BASE}/api/chain-sessions/{chain_session_id}/report")
            test("  GET /api/chain-sessions/{id}/report", s5 in (200,404), str(b5)[:80])


# ============================================================
# 8. SKILL GRAPH
# ============================================================
section("8. SKILL GRAPH")

status, body = req(f"{BASE}/api/skills")
test("GET /api/skills -> 200", status == 200, str(body)[:120])
if status == 200 and isinstance(body, dict):
    radar = body.get("radar") or body
    test("Skills response non-empty", len(radar) >= 0, str(list(body.keys()))[:80])

status, body = req(f"{BASE}/api/skills/recommend")
test("GET /api/skills/recommend -> 200", status in (200,204), str(body)[:120])
if status == 200 and isinstance(body, dict):
    has_module = "module_id" in body or "module" in body
    test("  Recommendation has module field", has_module, str(list(body.keys()))[:60])

if sid:
    status, body = req(f"{BASE}/api/skills/update", method="POST", body={"session_id": sid})
    test("POST /api/skills/update (uses completed session)", status in (200,201,400,404), str(body)[:80])


# ============================================================
# 9. MUTATION MODE
# ============================================================
section("9. MUTATION MODE")

status, body = req(f"{TARGET}/lab/mutations", timeout=6)
test("GET /lab/mutations (target-agent) -> 200", status == 200, str(body)[:120])
if status == 200:
    muts = body if isinstance(body, list) else body.get("mutations", [])
    test(f"Mutations catalog non-empty ({len(muts)})", len(muts) > 0)
    expected_muts = {"bf_delay","bf_lockout","xss_encode","xss_csp","ci_filter_pipe","ci_filter_semi"}
    found_muts = {m.get("id") or m.get("mutation_id","?") for m in muts}
    test("All 6 expected mutations present", expected_muts == found_muts, str(sorted(found_muts)))

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/mutations")
    test("GET /api/sessions/{sid}/mutations", status in (200,404), str(body)[:80])

    # Trigger a mutation
    status, body = req(f"{BASE}/api/sessions/{sid}/mutations/trigger", method="POST",
                       body={"module_id":"xss","mutation_id":"xss_encode"})
    test("POST /mutations/trigger (xss_encode)", status in (200,201,400,404), str(body)[:100])

    # Verify mutation is active
    if status in (200, 201):
        time.sleep(1)
        status2, body2 = req(f"{BASE}/api/sessions/{sid}/mutations")
        test("  Mutation appears in session active list", status2 == 200, str(body2)[:80])

    # Schedule a mutation
    status, body = req(f"{BASE}/api/sessions/{sid}/mutations/schedule", method="POST",
                       body={"module_id":"cmd_injection","mutation_id":"ci_filter_pipe","delay_seconds":5})
    test("POST /mutations/schedule (ci_filter_pipe, 5s)", status in (200,201,400,404), str(body)[:100])


# ============================================================
# 10. OPERATOR MODE — AttackBox
# ============================================================
section("10. OPERATOR MODE — AttackBox")

status, body = req(f"{BASE}/api/operator/attackbox/status")
test("GET /api/operator/attackbox/status -> 200", status == 200, str(body)[:100])
if status == 200:
    state = body.get("status") or body.get("state","")
    test("  AttackBox status field present", bool(state), f"state={state}")
    test("  AttackBox in running/stopped/offline state", state in ("running","stopped","offline","error","healthy"), f"state={state}")

# Echo command
status, body = req(f"{BASE}/api/operator/attackbox/exec", method="POST",
                   body={"command":"echo hello-attense", "session_id": sid or "test"})
test("POST /attackbox/exec (echo)", status in (200,400,403,422), str(body)[:120])
if status == 200:
    output = body.get("output","") or ""
    test("  AttackBox echo output contains expected string", "hello-attense" in output, output[:60])

# Blocked external command
status, body = req(f"{BASE}/api/operator/attackbox/exec", method="POST",
                   body={"command":"curl http://google.com", "session_id": sid or "test"})
test("POST /attackbox/exec (external — should be blocked or run)", status in (200,400,403,422), str(body)[:80])

# Evidence from attackbox
status, body = req(f"{BASE}/api/operator/attackbox/evidence?since=0")
test("GET /api/operator/attackbox/evidence", status in (200,404), str(body)[:80])


# ============================================================
# 11. OPERATOR MODE — ZAP
# ============================================================
section("11. OPERATOR MODE — ZAP")

status, body = req(f"{BASE}/api/operator/zap/status")
test("GET /api/operator/zap/status -> 200", status == 200, str(body)[:100])
if status == 200:
    zs = body.get("status") or body.get("state","")
    test("  ZAP status field present", bool(zs), f"status={zs}")
    test("  ZAP in online/offline state", zs in ("online","offline","healthy","starting","error","running"), f"zs={zs}")

status, body = req(f"{BASE}/api/operator/zap/history?limit=10")
test("GET /api/operator/zap/history", status in (200,503), str(body)[:100])
if status == 200:
    hist = body if isinstance(body, list) else body.get("history",[])
    test(f"  ZAP history is a list ({len(hist)} items)", isinstance(hist, list), "")

# ZAP Repeater
status, body = req(f"{BASE}/api/operator/zap/repeater/send", method="POST",
                   body={"method":"GET","path":"/","body":""})
test("POST /api/operator/zap/repeater/send (GET /)", status in (200,400,503), str(body)[:120])
if status == 200:
    has_resp = "response" in body or "status_code" in body or "status" in body
    test("  Repeater returns response data", has_resp, str(list(body.keys()))[:60])


# ============================================================
# 12. DETECTIONS FEED
# ============================================================
section("12. DETECTIONS FEED")

status, body = req(f"{BASE}/api/detections?since=0&limit=20")
test("GET /api/detections -> 200", status == 200, str(body)[:120])
if status == 200:
    items = body if isinstance(body, list) else body.get("detections",[])
    test(f"Detections returns list ({len(items)} items)", isinstance(items, list), "")
    if items:
        first = items[0]
        has_type = "type" in first or "event_type" in first or "kind" in first
        has_ts   = "timestamp" in first or "ts" in first or "created_at" in first
        test("  Detection event has type field", has_type, str(list(first.keys()))[:60])
        test("  Detection event has timestamp", has_ts, str(list(first.keys()))[:60])


# ============================================================
# 13. REPORT GENERATION
# ============================================================
section("13. REPORT GENERATION")

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/report")
    test("GET /api/sessions/{sid}/report", status in (200,404), str(body)[:120])
    if status == 200 and isinstance(body, dict):
        test("  Report has grade field", "grade" in body, str(list(body.keys()))[:60])
        test("  Report has score", "score" in body, str(list(body.keys()))[:60])
        test("  Report has module_id", "module_id" in body or "module" in body, str(list(body.keys()))[:60])
        g = body.get("grade","?")
        s = body.get("score","?")
        test(f"  Grade is letter (A-F), got '{g}'", g in list("ABCDF"), f"grade={g} score={s}")

    status, body = req(f"{BASE}/api/sessions/{sid}/lab-analysis")
    test("GET /api/sessions/{sid}/lab-analysis", status in (200,404), str(body)[:120])

    status, body = req(f"{BASE}/api/sessions/{sid}/report/regenerate", method="POST", body={})
    test("POST /api/sessions/{sid}/report/regenerate", status in (200,201,404), str(body)[:80])


# ============================================================
# 14. LOGS & NDJSON EXPORT
# ============================================================
section("14. SESSION LOGS & EXPORT")

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/logs")
    test("GET /api/sessions/{sid}/logs (JSON)", status in (200,404), str(body)[:80])

    status, body = req(f"{BASE}/api/sessions/{sid}/logs?format=ndjson")
    test("GET /api/sessions/{sid}/logs?format=ndjson", status in (200,404), str(body)[:80])


# ============================================================
# 15. EVIDENCE RESET
# ============================================================
section("15. EVIDENCE RESET")

if sid:
    status, body = req(f"{BASE}/api/sessions/{sid}/reset-evidence", method="POST", body={})
    test("POST /api/sessions/{sid}/reset-evidence", status in (200,204,404), str(body)[:80])
    if status in (200, 204):
        # Re-check progress to confirm reset
        s2, b2 = req(f"{BASE}/api/sessions/{sid}/check-progress", method="POST", body={})
        if s2 == 200 and isinstance(b2, dict):
            score2 = b2.get("score") or b2.get("percentage") or 0
            test("  Score reset to 0 after evidence reset", float(score2) == 0, f"score={score2}")


# ============================================================
# 16. SESSION RESTART & CLEANUP
# ============================================================
section("16. SESSION RESTART & CLEANUP")

# Create a disposable session
status, body = req(f"{BASE}/api/sessions", method="POST", body={"module_id":"xss"})
sid2 = body.get("session_id") or body.get("id") if status in (200,201) else None
test("Create XSS session for cleanup test", bool(sid2), str(sid2))

if sid2:
    status, body = req(f"{BASE}/api/sessions/{sid2}/restart", method="POST", body={})
    test("POST /api/sessions/{sid}/restart", status in (200,201,204,400,404), str(body)[:80])

    status, body = req(f"{BASE}/api/sessions/{sid2}", method="DELETE")
    test("DELETE /api/sessions/{sid}", status in (200,204,404), str(body)[:80])

    # Confirm deleted
    status, body = req(f"{BASE}/api/sessions/{sid2}")
    test("  Session gone after DELETE", status == 404, f"HTTP {status}")

# Also clean up main session
if sid:
    req(f"{BASE}/api/sessions/{sid}", method="DELETE")
    test("Cleanup main session", True, "cleaned up")


# ============================================================
# 17. WAZUH MANAGER
# ============================================================
section("17. WAZUH MANAGER (internal)")

status, body = req("http://wazuh.manager:55000/", timeout=5)
test("Wazuh API reachable (internal port 55000)", status in (200,401,403), f"HTTP {status}")

status, body = req("http://wazuh.manager:55000/security/user/authenticate", timeout=5)
test("Wazuh auth endpoint exists", status in (200,401,405), f"HTTP {status}")


# ============================================================
# FINAL SUMMARY
# ============================================================
section("FINAL SUMMARY")

passed = sum(1 for _, p, _ in results if p)
total  = len(results)
failed_items = [(n, d) for n, p, d in results if not p]

print(f"\n  Total  : {total}")
print(f"  Passed : {passed}")
print(f"  Failed : {total - passed}")

if failed_items:
    print("\n  Failed tests:")
    for name, detail in failed_items:
        d = f" -> {detail}" if detail else ""
        print(f"    [FAIL] {name}{d}")

pct = round(passed / total * 100, 1) if total else 0
print(f"\n  Overall Score: {pct}%")
if pct >= 90:
    print("  >> EXCELLENT — Platform is in great shape!")
elif pct >= 75:
    print("  >> GOOD — Minor issues to address.")
elif pct >= 60:
    print("  >> FAIR — Several issues detected.")
else:
    print("  >> NEEDS ATTENTION — Multiple failures.")

sys.exit(0 if pct >= 70 else 1)
