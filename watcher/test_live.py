"""
watcher/test_live.py
Live integration test — hits real Ollama and real BlueTeam API.
Run from project root: python3 watcher/test_live.py
"""
import json, time, requests, sys

BLUETEAM_URL   = "http://localhost:8010"
COORDINATOR_URL = "http://localhost:8000"
OLLAMA_URL     = "http://localhost:11434"
OLLAMA_MODEL   = "llama3.2"
INCIDENT_ID    = "live-test-001"
SCENARIO_ID    = "APP-01"
ANALYST_ID     = "analyst-test"

# ── 1. Create a watcher session ──────────────────────────────────────────────
print("\n[1] Creating watcher session...")
r = requests.post(f"{COORDINATOR_URL}/session/watcher",
                  json={"scenario_id": SCENARIO_ID, "incident_id": INCIDENT_ID})
session = r.json()
print(f"    Session code: {session['code']}")
print(f"    started_at_unix: {session['started_at_unix']}")
session_start = session["started_at_unix"]

# ── 2. Simulate a realistic SOC command batch with timestamps ────────────────
now = time.time()
commands_with_timestamps = [
    (int(now - session_start) + 30,  "cat /var/log/wazuh/alerts.json"),
    (int(now - session_start) + 32,  "grep -i 'xss' /var/log/nginx/access.log"),
    (int(now - session_start) + 35,  "tail -f /var/log/nginx/error.log"),
    (int(now - session_start) + 120, "curl -s http://10.0.0.5/test?name=<script>alert(1)</script>"),
    (int(now - session_start) + 180, "iptables -A INPUT -s 10.0.0.5 -j DROP"),
    (int(now - session_start) + 182, "iptables -L | grep DROP"),
]

# ── 3. Call Ollama with the real classification prompt ───────────────────────
print("\n[2] Sending command batch to Ollama for classification...")
numbered = "\n".join(f"{i+1}. [t=+{ts}s] {cmd}"
                     for i, (ts, cmd) in enumerate(commands_with_timestamps))
prompt = f"""You are a SOC event classifier for a Blue Team exercise.
Analyst: {ANALYST_ID}
Commands with timestamps:
{numbered}

Classify any significant SOC response actions.
Return ONLY valid JSON — no explanation, no markdown:
{{"events": [{{"event_type": "<type>", "t_offset_sec": <int>, "detail": "<one sentence>"}}]}}

Valid event_types: investigation_started, incident_confirmed, containment_initiated, containment_succeeded, alert_denied
If no SOC action: {{"events": []}}"""

r = requests.post(f"{OLLAMA_URL}/api/generate",
                  json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                  timeout=120)
raw = r.json()["response"]
print(f"    Raw LLM response:\n    {raw}")

try:
    classified = json.loads(raw)
    events = classified.get("events", [])
    print(f"    Classified {len(events)} event(s)")
except json.JSONDecodeError:
    print("    ERROR: LLM returned non-JSON — classification failed")
    sys.exit(1)

# ── 4. Post each classified event to BlueTeam API ───────────────────────────
valid_types = {"investigation_started","incident_confirmed",
               "containment_initiated","containment_succeeded","alert_denied"}
print("\n[3] Posting events to BlueTeam API...")
for ev in events:
    if ev.get("event_type") not in valid_types:
        print(f"    SKIP — invalid event_type: {ev.get('event_type')}")
        continue
    payload = {
        "analyst_id":   ANALYST_ID,
        "incident_id":  INCIDENT_ID,
        "scenario_id":  SCENARIO_ID,
        "event_type":   ev["event_type"],
        "t_offset_sec": ev.get("t_offset_sec", 0),
        "detail":       ev.get("detail", ""),
        "timestamp":    time.time(),
    }
    r = requests.post(f"{BLUETEAM_URL}/blueteam/analyst-action", json=payload)
    print(f"    POST {ev['event_type']} → {r.status_code}")

# ── 5. Read everything back ──────────────────────────────────────────────────
print("\n[4] Reading events back from BlueTeam API...")
r = requests.get(f"{BLUETEAM_URL}/blueteam/analyst-actions/{INCIDENT_ID}")
result = r.json()
print(f"    Total stored: {result['count']}")
for a in result["actions"]:
    print(f"    t=+{a['t_offset_sec']}s  {a['analyst_id']}  →  {a['event_type']}")
    print(f"           {a['detail']}")

print("\n✓ Live test complete." if result["count"] > 0 else "\n✗ No events stored — check logs.")
