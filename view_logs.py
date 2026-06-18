"""
view_logs.py — View the analyst actions log in two formats.

  SECTION 1 — Raw log
    Exactly what is stored in the file, one line per event.

  SECTION 2 — Ollama plain-English version
    Each event converted to a single readable sentence by Ollama.
    No reports, no paragraphs — one line in, one line out.

Run after test_cycle.py to see both views side by side.
"""

import json
import subprocess
import sys
import time

SEP  = "─" * 60
SEP2 = "═" * 60


# ── Read the log file ─────────────────────────────────────────────────────────

raw_output = subprocess.run(
    ["docker", "exec", "attense_app",
     "cat", "/attense/actions/analyst_actions.jsonl"],
    capture_output=True, text=True,
)

lines = [l.strip() for l in raw_output.stdout.splitlines() if l.strip()]

if not lines:
    print("\nLog file is empty. Run test_cycle.py first.\n")
    sys.exit(0)

events = []
for line in lines:
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError:
        pass


# ── SECTION 1: Raw log ────────────────────────────────────────────────────────

print(f"\n{SEP2}")
print(f"  SECTION 1 — RAW LOG  ({len(events)} events)")
print(f"{SEP2}\n")

for line in lines:
    print(f"  {line}")


# ── SECTION 2: Ollama plain-English ──────────────────────────────────────────

print(f"\n{SEP2}")
print(f"  SECTION 2 — PLAIN ENGLISH  (via Ollama llama3.2)")
print(f"{SEP2}\n")
print("  Converting each event... (takes ~20 seconds)\n")

# Build a numbered list of events for Ollama
event_lines = "\n".join(
    f"{i+1}. analyst={e.get('analyst_id')}  event={e.get('event_type')}  "
    f"scenario={e.get('scenario_id')}  t=+{e.get('t_offset_sec')}s  "
    f"detail={e.get('detail','')}"
    for i, e in enumerate(events)
)

prompt = (
    "Convert each numbered SOC event below into ONE plain English sentence. "
    "Format: '<number>. <sentence>' — nothing else, no extra text.\n"
    "Each sentence should say: who did what, on which scenario, and what it means.\n\n"
    f"Events:\n{event_lines}"
)

script = (
    "import json, urllib.request\n"
    f"p = json.dumps({{'model':'llama3.2','prompt':{json.dumps(prompt)},'stream':False}}).encode()\n"
    "req = urllib.request.Request('http://ollama:11434/api/generate', data=p, "
    "headers={'Content-Type':'application/json'})\n"
    "print(json.loads(urllib.request.urlopen(req, timeout=180).read())['response'])\n"
)

result = subprocess.run(
    ["docker", "exec", "-i", "attense_red_team_backend", "python3"],
    input=script.encode(), capture_output=True, timeout=200,
)

ollama_text = result.stdout.decode().strip()

if result.returncode != 0 or not ollama_text:
    print("  Ollama unavailable — showing formatted version instead:\n")
    for e in events:
        ts = time.strftime('%H:%M:%S', time.localtime(e.get('stored_at', 0)))
        src = "hive" if e.get('t_offset_sec') == 0 else "watcher"
        print(f"  {ts}  [{src}]  {e.get('analyst_id')} did {e.get('event_type')} — {e.get('detail','')}")
else:
    # Print Ollama output with timestamps alongside
    ol_lines = [l.strip() for l in ollama_text.splitlines() if l.strip()]
    for i, ol_line in enumerate(ol_lines):
        ts = ""
        if i < len(events):
            ts = time.strftime('%H:%M:%S', time.localtime(events[i].get('stored_at', 0)))
        print(f"  {ts}  {ol_line}")

print(f"\n{SEP2}\n")
