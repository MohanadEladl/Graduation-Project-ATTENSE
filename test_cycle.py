"""
test_cycle.py — ATTENSE full pipeline test.

Run this to generate a clean test incident in the log file.
After it completes, run view_logs.py to see the results.

Two paths fire in sequence:

  PATH A — TheHive Webhook
    Simulates what happens when an analyst works a case in TheHive UI.
    Each action (open case, update, add task, close) fires a webhook
    which the system translates and writes to the log.

  PATH B — Watcher Agent + Ollama
    Simulates the Watcher Agent running on an analyst's machine.
    Raw terminal commands are sent to Ollama for classification,
    then posted to the log as structured analyst actions.
"""

import json
import re
import subprocess
import time

import requests

BLUETEAM  = "http://localhost:8010"
INCIDENT  = f"test-{int(time.time())}"
SCENARIO  = "APP-01"
ANALYST   = "alice@lab.local"
CASE_ID   = f"~{int(time.time()) % 100000}"
SEP = "─" * 60


def _post_webhook(payload: dict, label: str):
    r = requests.post(f"{BLUETEAM}/internal/webhook/hive", json=payload, timeout=10)
    d = r.json()
    result = d.get("attense_event_type", d.get("reason", "?"))
    ok = "✓" if d.get("status") == "translated" else "·"
    print(f"  {ok}  {label:48s}  →  {result}")


def _call_ollama(prompt: str) -> str:
    script = (
        "import json, urllib.request\n"
        f"p = json.dumps({{'model':'llama3.2','prompt':{json.dumps(prompt)},'stream':False}}).encode()\n"
        "req = urllib.request.Request('http://ollama:11434/api/generate', data=p, "
        "headers={'Content-Type':'application/json'})\n"
        "print(json.loads(urllib.request.urlopen(req, timeout=180).read())['response'])\n"
    )
    r = subprocess.run(
        ["docker", "exec", "-i", "attense_red_team_backend", "python3"],
        input=script.encode(), capture_output=True, timeout=200,
    )
    return r.stdout.decode().strip()


def _case(extra: dict = {}) -> dict:
    base = {
        "_id":   CASE_ID,
        "id":    CASE_ID,
        "title": f"XSS Attack — {INCIDENT}",
        "tags":  [f"attense:incident-{INCIDENT}", SCENARIO],
        "status": "Open",
    }
    base.update(extra)
    return base


print(f"\n{SEP}")
print(f"  ATTENSE TEST CYCLE  |  incident = {INCIDENT}")
print(f"{SEP}\n")

# ── PATH A: TheHive Webhook ───────────────────────────────────────────────────
print("PATH A — TheHive Webhook\n")

TASK_ID = f"~task-{int(time.time()) % 100000}"

_post_webhook({
    "objectType": "case", "operation": "create",
    "createdBy": ANALYST, "object": _case(),
}, "case/create  (analyst opens case)")

time.sleep(0.3)

_post_webhook({
    "objectType": "case", "operation": "update",
    "updatedBy": ANALYST,
    "object": _case({"status": "Open"}),
    "details": {"status": "Open"},
}, "case/update Open  (analyst confirms incident)")

time.sleep(0.3)

_post_webhook({
    "objectType": "case_task", "operation": "create",
    "createdBy": ANALYST, "rootId": CASE_ID,
    "object": {
        "_id": TASK_ID, "id": TASK_ID,
        "title": "Block attacker IP via Wazuh",
        "status": "InProgress", "case": CASE_ID,
    },
}, "case_task/create InProgress  (containment started)")

time.sleep(0.3)

_post_webhook({
    "objectType": "case_task", "operation": "update",
    "updatedBy": ANALYST, "rootId": CASE_ID,
    "object": {
        "_id": TASK_ID, "id": TASK_ID,
        "title": "Block attacker IP via Wazuh",
        "status": "Completed", "case": CASE_ID,
    },
    "details": {"status": "Completed"},
}, "case_task/update Completed  (containment done)")

time.sleep(0.3)

_post_webhook({
    "objectType": "case", "operation": "update",
    "updatedBy": ANALYST,
    "object": _case({"status": "Resolved", "resolutionStatus": "TruePositive"}),
    "details": {"status": "Resolved", "resolutionStatus": "TruePositive"},
}, "case/update Resolved+TruePositive  (incident closed)")

# ── PATH B: Watcher Agent + Ollama ────────────────────────────────────────────
print(f"\nPATH B — Watcher Agent + Ollama\n")

session_start = time.time() - 200
commands = [
    (20,  "cat /var/log/wazuh/alerts.json"),
    (35,  "grep -i 'xss\\|<script>' /var/log/nginx/access.log"),
    (55,  "tail -100 /var/log/nginx/access.log | grep 10.0.0.99"),
    (110, "curl -s 'http://10.0.0.99/?q=<script>alert(1)</script>'"),
    (145, "iptables -A INPUT -s 10.0.0.99 -j DROP"),
    (150, "iptables -L | grep DROP"),
]

numbered = "\n".join(f"{i+1}. [t=+{t}s] {cmd}" for i, (t, cmd) in enumerate(commands))
prompt = (
    f"Analyst: analyst-alice\nCommands:\n{numbered}\n\n"
    "Classify significant SOC response actions. Return ONLY JSON:\n"
    '{"events": [{"event_type": "<type>", "t_offset_sec": <int>, "detail": "<one sentence>"}]}\n'
    "Valid types: investigation_started, incident_confirmed, containment_initiated, "
    "containment_succeeded, alert_denied\n"
    'No action: {"events": []}'
)

print("  Sending commands to Ollama for classification...")
raw = _call_ollama(prompt)

match = re.search(r'\{.*"events"\s*:.*\}', raw, re.DOTALL)
events = []
if match:
    try:
        events = json.loads(match.group(0)).get("events", [])
    except json.JSONDecodeError:
        pass

valid = {"investigation_started","incident_confirmed","containment_initiated",
         "containment_succeeded","alert_denied"}
posted = 0
for ev in events:
    if ev.get("event_type") not in valid:
        continue
    r = requests.post(f"{BLUETEAM}/blueteam/analyst-action", json={
        "analyst_id":   "analyst-alice",
        "incident_id":  INCIDENT,
        "scenario_id":  SCENARIO,
        "event_type":   ev["event_type"],
        "t_offset_sec": int(ev.get("t_offset_sec", 0)),
        "detail":       str(ev.get("detail", ""))[:300],
        "timestamp":    session_start + int(ev.get("t_offset_sec", 0)),
    }, timeout=10)
    ok = "✓" if r.status_code in (200, 201) else "✗"
    print(f"  {ok}  watcher → {ev['event_type']:30s}  t=+{ev.get('t_offset_sec')}s")
    posted += 1

print(f"\n  Watcher posted {posted} event(s) via Ollama")

# ── Summary ───────────────────────────────────────────────────────────────────
time.sleep(0.5)
total = requests.get(f"{BLUETEAM}/blueteam/analyst-actions/{INCIDENT}").json().get("count", 0)
print(f"\n{SEP}")
print(f"  Done.  {total} events written for incident  {INCIDENT}")
print(f"  Run:   python3 view_logs.py")
print(f"{SEP}\n")
