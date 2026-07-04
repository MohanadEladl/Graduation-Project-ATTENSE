"""
test_full_cycle.py — Full end-to-end ATTENSE pipeline test.

Two parallel paths into analyst_actions.jsonl:

  PATH A: TheHive Webhook
    Simulated Hive payloads → POST /internal/webhook/hive
    → hive_event_translator → analyst_action_extractor → JSONL

  PATH B: Watcher Agent + Ollama
    Raw SOC commands → Ollama llama3.2 → POST /blueteam/analyst-action → JSONL

  Then: print raw JSONL + human-readable summary side by side.
"""

import json
import re
import subprocess
import time

import requests

BLUETEAM   = "http://localhost:8010"
INCIDENT   = f"demo-{int(time.time())}"   # unique per run
SCENARIO   = "APP-01"
ANALYST    = "alice@lab.local"             # Hive-style → slugified to analyst-alice
CASE_ID    = f"~{int(time.time()) % 100000}"   # fake Hive _id
SEP = "─" * 65

def webhook(payload: dict, label: str):
    r = requests.post(f"{BLUETEAM}/internal/webhook/hive", json=payload, timeout=10)
    d = r.json()
    status = d.get("status", "?")
    event  = d.get("attense_event_type", "ignored")
    print(f"  [{r.status_code}] {label:45s} → {status} ({event})")

def ollama_generate(prompt: str) -> str:
    """Call Ollama HTTP API via a container on the same Docker network."""
    script = (
        "import json, urllib.request\n"
        f"payload = json.dumps({{'model': 'llama3.2', 'prompt': {json.dumps(prompt)}, 'stream': False}}).encode()\n"
        "req = urllib.request.Request('http://ollama:11434/api/generate', data=payload, "
        "headers={'Content-Type': 'application/json'})\n"
        "resp = urllib.request.urlopen(req, timeout=180)\n"
        "print(json.loads(resp.read())['response'])\n"
    )
    result = subprocess.run(
        ["docker", "exec", "-i", "attense_red_team_backend", "python3"],
        input=script.encode(), capture_output=True, timeout=200,
    )
    if result.returncode != 0:
        return f"[Ollama error: {result.stderr.decode()[:200]}]"
    return result.stdout.decode().strip()


# Case object reused across webhook calls
def _case_obj(extra: dict = {}) -> dict:
    base = {
        "_id":      CASE_ID,
        "id":       CASE_ID,
        "title":    f"XSS Exploitation — {INCIDENT}",
        "tags":     [f"attense:incident-{INCIDENT}", SCENARIO],
        "status":   "Open",
        "severity": 3,
    }
    base.update(extra)
    return base


print(f"\n{SEP}")
print(f"  ATTENSE FULL CYCLE TEST  |  incident={INCIDENT}")
print(f"{SEP}\n")

# ─── PATH A: TheHive Webhook ──────────────────────────────────────────────────
print(f"PATH A — TheHive Webhook events\n")

# 1. Analyst creates case (alert investigated → case opened)
webhook({
    "objectType": "case",
    "operation":  "create",
    "createdBy":  ANALYST,
    "object":     _case_obj(),
}, "case/create → investigation_started")
time.sleep(0.2)

# 2. Case updated → Open (analyst reviewing)
webhook({
    "objectType": "case",
    "operation":  "update",
    "updatedBy":  ANALYST,
    "object":     _case_obj({"status": "Open"}),
    "details":    {"status": "Open"},
}, "case/update Open → incident_confirmed")
time.sleep(0.2)

# 3. Containment task created (Isolate Host)
TASK_ID = f"~task-{int(time.time()) % 100000}"
webhook({
    "objectType": "case_task",
    "operation":  "create",
    "createdBy":  ANALYST,
    "rootId":     CASE_ID,
    "object": {
        "_id":    TASK_ID,
        "id":     TASK_ID,
        "title":  "Isolate host",
        "status": "InProgress",
        "case":   CASE_ID,
    },
}, "case_task/create InProgress → containment_initiated")
time.sleep(0.2)

# 4. Containment task completed
webhook({
    "objectType": "case_task",
    "operation":  "update",
    "updatedBy":  ANALYST,
    "rootId":     CASE_ID,
    "object": {
        "_id":    TASK_ID,
        "id":     TASK_ID,
        "title":  "Isolate host",
        "status": "Completed",
        "case":   CASE_ID,
    },
    "details": {"status": "Completed"},
}, "case_task/update Completed → containment_succeeded")
time.sleep(0.2)

# 5. Case closed as TruePositive
webhook({
    "objectType": "case",
    "operation":  "update",
    "updatedBy":  ANALYST,
    "object":     _case_obj({"status": "Resolved", "resolutionStatus": "TruePositive"}),
    "details":    {"status": "Resolved", "resolutionStatus": "TruePositive"},
}, "case/update Resolved+TruePositive → incident_ended")
time.sleep(0.2)

# ─── PATH B: Watcher Agent + Ollama ──────────────────────────────────────────
print(f"\n{SEP}")
print("PATH B — Watcher Agent: raw commands → Ollama → analyst-action\n")

session_start = time.time() - 200
commands = [
    (30,  "cat /var/log/wazuh/alerts.json"),
    (45,  "grep -i 'xss\\|<script>' /var/log/nginx/access.log"),
    (60,  "tail -50 /var/log/nginx/access.log | grep 10.0.0.99"),
    (120, "curl -s 'http://10.0.0.99/?q=<script>alert(1)</script>'"),
    (150, "iptables -A INPUT -s 10.0.0.99 -j DROP"),
    (155, "iptables -L | grep DROP"),
]

numbered = "\n".join(f"{i+1}. [t=+{t}s] {cmd}" for i,(t,cmd) in enumerate(commands))
classify_prompt = (
    f"Analyst: analyst-alice\n"
    f"Commands:\n{numbered}\n\n"
    "Classify significant SOC response actions. Return ONLY JSON:\n"
    '{"events": [{"event_type": "<type>", "t_offset_sec": <int>, "detail": "<one sentence>"}]}\n'
    "Valid types: investigation_started, incident_confirmed, containment_initiated, containment_succeeded, alert_denied\n"
    'No SOC action: {"events": []}'
)

print("  Sending command batch to Ollama llama3.2 ...")
raw_llm = ollama_generate(classify_prompt)
print(f"  Raw LLM output:\n    {raw_llm}\n")

json_match = re.search(r'\{.*"events"\s*:.*\}', raw_llm, re.DOTALL)
events = []
if json_match:
    try:
        events = json.loads(json_match.group(0)).get("events", [])
    except json.JSONDecodeError:
        print("  WARN: could not parse LLM JSON")

valid_types = {"investigation_started","incident_confirmed","containment_initiated","containment_succeeded","alert_denied"}
posted = 0
for ev in events:
    if ev.get("event_type") not in valid_types:
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
    status_str = "OK" if r.status_code in (200,201) else f"ERROR {r.status_code}"
    print(f"  [{status_str}] watcher → {ev['event_type']}  t=+{ev.get('t_offset_sec')}s")
    posted += 1

print(f"\n  Watcher posted {posted} event(s)")

# ─── Raw JSONL + readable summary ────────────────────────────────────────────
time.sleep(0.5)
print(f"\n{SEP}")
print(f"RAW JSONL — /attense/actions/analyst_actions.jsonl  (this incident)")
print(f"{SEP}\n")

all_lines = subprocess.run(
    ["docker", "exec", "attense_app", "cat", "/attense/actions/analyst_actions.jsonl"],
    capture_output=True, text=True,
).stdout.splitlines()

this_run = [l for l in all_lines if INCIDENT in l]
print(f"  {len(this_run)} lines  (total in file: {len(all_lines)})\n")
for line in this_run:
    print(f"  {line}")

print(f"\n{SEP}")
print(f"  READABLE SUMMARY")
print(f"{SEP}\n")
for line in this_run:
    try:
        d = json.loads(line)
        ts = time.strftime('%H:%M:%S', time.localtime(d.get('stored_at', 0)))
        src = "hive  " if d.get('t_offset_sec') == 0 else "watcher"
        print(f"  {ts}  [{src}]  {d.get('event_type'):30s}  {d.get('analyst_id')}")
        print(f"            {d.get('detail', '')}")
    except Exception:
        pass

print(f"\n{SEP}")
print(f"  Done.  {len(this_run)} events recorded for incident {INCIDENT}")
print(f"{SEP}\n")
