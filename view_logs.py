"""
view_logs.py — View analyst action logs in two formats.

  SECTION 1 — Raw log
    Lists every per-analyst file in /attense/actions/, shows which
    analyst it belongs to, then prints every event as raw JSON.

  SECTION 2 — Plain English (via Ollama llama3.2)
    Each event converted to one readable sentence, grouped by analyst.

Run after test_cycle.py to see both views.
"""

import json
import subprocess
import sys
import time

SEP  = "─" * 60
SEP2 = "═" * 60


# ── Discover all log files in the actions directory ───────────────────────────

ls_output = subprocess.run(
    ["docker", "exec", "attense_app", "ls", "/attense/actions/"],
    capture_output=True, text=True,
)
all_files = [f.strip() for f in ls_output.stdout.splitlines() if f.strip().endswith(".jsonl")]

if not all_files:
    print("\nNo log files found. Run test_cycle.py first.\n")
    sys.exit(0)

# Read each file and group events by analyst
analyst_events: dict[str, list[dict]] = {}   # analyst_id → list of events
all_events: list[dict] = []

for fname in sorted(all_files):
    cat = subprocess.run(
        ["docker", "exec", "attense_app", "cat", f"/attense/actions/{fname}"],
        capture_output=True, text=True,
    )
    file_events = []
    for line in cat.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            file_events.append(rec)
            all_events.append(rec)
        except json.JSONDecodeError:
            pass

    if file_events:
        analyst = file_events[0].get("analyst_id", fname)
        analyst_events.setdefault(analyst, []).extend(file_events)


# ── SECTION 1: Raw log ────────────────────────────────────────────────────────

print(f"\n{SEP2}")
print(f"  SECTION 1 — RAW LOG")
print(f"  {len(all_files)} file(s) found  |  {len(all_events)} total events")
print(f"{SEP2}")

for fname in sorted(all_files):
    analyst = fname.replace(".jsonl", "")
    events_in_file = analyst_events.get(
        next((e.get("analyst_id","?") for e in all_events if True), "?"), []
    )
    cat = subprocess.run(
        ["docker", "exec", "attense_app", "cat", f"/attense/actions/{fname}"],
        capture_output=True, text=True,
    )
    lines = [l.strip() for l in cat.stdout.splitlines() if l.strip()]
    print(f"\n  FILE: {fname}  ({len(lines)} events)")
    print(f"  {SEP}")
    for line in lines:
        print(f"    {line}")


# ── SECTION 2: Ollama plain-English per analyst ───────────────────────────────

print(f"\n{SEP2}")
print(f"  SECTION 2 — PLAIN ENGLISH  (via Ollama llama3.2)")
print(f"{SEP2}\n")
print("  Converting events... (takes ~20 seconds)\n")

for analyst_id, events in sorted(analyst_events.items()):
    print(f"  {SEP}")
    print(f"  ANALYST: {analyst_id}  ({len(events)} events)")
    print(f"  {SEP}\n")

    event_lines = "\n".join(
        f"{i+1}. event={e.get('event_type')}  scenario={e.get('scenario_id')}  "
        f"t=+{e.get('t_offset_sec')}s  detail={e.get('detail','')}"
        for i, e in enumerate(events)
    )

    prompt = (
        f"The following SOC events were recorded for analyst '{analyst_id}'.\n"
        "Convert each numbered event into ONE plain English sentence. "
        "Format exactly: '<number>. <sentence>' — nothing else, no extra text.\n"
        f"Always refer to the analyst by name: {analyst_id}.\n"
        "Each sentence must say: who did what, on which scenario, and what it means.\n\n"
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

    if result.returncode != 0 or not result.stdout.strip():
        print("  [Ollama unavailable — showing formatted fallback]\n")
        for e in events:
            ts = time.strftime('%H:%M:%S', time.localtime(e.get('stored_at', 0)))
            print(f"  {ts}  {e.get('event_type')}  |  {e.get('detail','')}")
    else:
        ol_lines = [l.strip() for l in result.stdout.decode().splitlines() if l.strip()]
        for i, sentence in enumerate(ol_lines):
            ts = ""
            if i < len(events):
                ts = time.strftime('%H:%M:%S', time.localtime(events[i].get('stored_at', 0)))
            print(f"  {ts}  {sentence}")

    print()

print(f"{SEP2}\n")
