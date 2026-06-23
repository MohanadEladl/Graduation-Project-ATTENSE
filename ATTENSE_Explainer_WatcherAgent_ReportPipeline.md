# ATTENSE Technical Explainer: Watcher Agent + Report Pipeline

---

## WATCHER AGENT

### What it does

The Watcher Agent runs on a **Linux analyst machine** and passively monitors everything the analyst does in the terminal. It reads new EXECVE records from the kernel's auditd log in real time, batches all non-noise commands every 30 seconds, sends the batch to a locally-running Ollama LLM (llama3.2 by default), and asks it to classify any SOC response actions it sees. Classified events are immediately POSTed to the Blue Team API, which persists them to disk for later scoring by the evaluation pipeline.

---

### Files and their jobs

| File | Job |
|---|---|
| `watcher/agent.py` | Main loop: tails `/var/log/audit/audit.log`, parses EXECVE lines, batches commands, calls Ollama, POSTs events to BlueTeam API |
| `watcher/identity.py` | Startup prompt: asks the analyst for their name and session code. Saves name to `~/.attense_identity` for re-use. Returns `(analyst_id, session_code)` in `analyst-<slug>` format |
| `watcher/coordinator_client.py` | Polls `GET {COORDINATOR_URL}/session/watcher/{session_code}` (Red Team backend, default port 8000) every 5 seconds until `status == "active"`. Returns `(incident_id, scenario_id, started_at_unix)` — the three pieces the agent needs to tag every event it reports |
| `attense-app/ATTENSE_app/events/allowed_events.py` | The canonical set of all valid event type strings. 14 types total. This is the definition; anything not in here is invalid in the ATTENSE data model |
| `attense-app/ATTENSE_app/blueteam/config/constants.py` | Same 14 event types as named Python constants (e.g. `EVENT_EVIDENCE_PRESERVED = "evidence_preserved"`) plus incident statuses, timing thresholds, and containment strategies. All other code imports from here — nothing hardcodes strings |

---

### Actual data flow

```
auditd kernel subsystem
    │
    └─ writes EXECVE records to /var/log/audit/audit.log
         format: type=EXECVE msg=audit(1717001234.567:123) a0="cp" a1="-r" a2="/var/log" ...
    │
    ▼
agent.py: _tail_audit_log(path)
    │  opens file, seeks to END (does not replay old commands)
    │  yields new lines every 200ms via readline() poll
    │  detects log rotation via inode change
    │
    ▼
agent.py: _parse_execve_line(line)
    │  extracts epoch from msg=audit(EPOCH:...)
    │  reconstructs command from a0, a1, a2... argument fields
    │  (falls back to hex-decode for encoded args)
    │  returns (epoch_float, "command string") or None
    │
    ▼
noise filter: _NOISE_PATTERNS regex
    │  drops: auditctl, ausearch, auditd, aureport, python*, /proc/, /sys/,
    │         systemd, dbus, cron, sshd, watcher.py, agent.py itself
    │
    ▼
pending list accumulates: [(t_offset_sec, "command"), ...]
    │  t_offset_sec = epoch - session_start (from coordinator)
    │
    ▼  (every BATCH_INTERVAL seconds, default 30s)
agent.py: _classify_with_ollama(analyst_id, commands)
    │
    │  POSTs to: {OLLAMA_URL}/api/generate   (default: http://localhost:11434)
    │  model: llama3.2 (or $OLLAMA_MODEL)
    │  stream: false
    │
    │  Ollama returns: {"response": "{\"events\": [...]}"}
    │  extracts JSON with regex: r'\{.*"events"\s*:.*\}'
    │  validates each event_type against _VALID_EVENT_TYPES — drops hallucinations
    │
    ▼
agent.py: _post_action(...)
    │
    │  POSTs to: {BLUETEAM_URL}/blueteam/analyst-action   (default: http://localhost:8010)
    │  body:
    │    {
    │      "analyst_id":   "analyst-alice",
    │      "incident_id":  "wazuh-1782165271.6613",   ← from coordinator
    │      "scenario_id":  "APP-01",                  ← from coordinator
    │      "event_type":   "evidence_preserved",
    │      "t_offset_sec": 142,
    │      "detail":       "Analyst archived web logs to evidence store",
    │      "timestamp":    1718001234.567
    │    }
    │
    ▼
attense-app/ATTENSE_app/blueteam/routers/analyst_actions.py
    │  endpoint: POST /blueteam/analyst-action
    │  validates event_type against AnalystEventType enum
    │  appends to in-memory dict keyed by incident_id
    │  writes to disk:
    │
    └─ /attense/actions/<analyst_id>_<YYYY-MM-DD>.jsonl
         one JSON object per line:
         {"analyst_id":"analyst-alice","incident_id":"wazuh-...","scenario_id":"APP-01",
          "event_type":"evidence_preserved","t_offset_sec":142,"detail":"...","timestamp":1718001234.567,"stored_at":1718001235.1}
```

---

### Current valid event types and the watcher/TheHive split

**Full `_VALID_EVENT_TYPES` in `watcher/agent.py`:**

```python
_VALID_EVENT_TYPES = {
    "investigation_started",
    "incident_confirmed",
    "containment_initiated",
    "containment_succeeded",
    "alert_denied",
    # v2.0.0 — terminal-inferable post-containment actions
    "evidence_preserved",       # copy/hash/archive artifacts to evidence store
    "eradication_completed",    # remove malicious files/processes/services/accounts
    "recovery_validated",       # health-check / service-status probes confirm normal operation
}
```

**Of the 5 new v2.0.0 event types, 3 go through the watcher and 2 go through TheHive:**

| Event type | Source | Why |
|---|---|---|
| `evidence_preserved` | Watcher (auditd) | Maps to terminal commands: `cp`, `tar`, `sha256sum`, `tcpdump -w`. These produce EXECVE records that Ollama can classify |
| `eradication_completed` | Watcher (auditd) | Maps to: `rm`, `pkill`, `userdel`, `apt remove`, `systemctl disable`. All produce EXECVE records |
| `recovery_validated` | Watcher (auditd) | Maps to: `curl`, `ping`, `systemctl status`, `wget`, `nc`. All produce EXECVE records |
| `dismissal_approved` | TheHive webhook | Requires a human decision and sign-off inside TheHive (a second analyst approving the dismissal). There is no shell command that means "I approve dismissing this alert" — it is a UI action, not a terminal action |
| `lessons_learned_recorded` | TheHive webhook | Requires an analyst to add a case comment or close note in TheHive stating lessons learned. No terminal footprint |

The Ollama prompt in `agent.py` explicitly describes the three watcher-eligible new types with example commands to help the model classify them correctly. `dismissal_approved` and `lessons_learned_recorded` are intentionally absent from the watcher's type set — they arrive via the TheHive webhook pipeline instead (`webhook_router.py` and `hive_event_translator.py`).

---

### Manual test: step by step

**Prerequisites:** Linux machine with auditd running, Ollama running with llama3.2 pulled, Blue Team API container running (`attense_app` on port 8010), Red Team coordinator running on port 8000, and an active watcher session registered via the Red Team UI.

> **Platform requirement — Linux only.**
> The watcher agent requires a running `auditd` daemon and access to `/var/log/audit/audit.log`. This was confirmed during live testing to be **unavailable on macOS** — auditd does not exist on macOS, and none of the containers in the current `docker-compose.yml` have auditd configured. If you are on macOS, you cannot run the watcher at all in the current setup. Use **Step 6 (direct curl injection)** as the only available substitute until a Linux test environment is set up.

**Step 1 — Start the watcher**

```bash
cd watcher/
pip install -r requirements.txt  # first time only
BLUETEAM_URL=http://<host>:8010 \
COORDINATOR_URL=http://<host>:8000 \
OLLAMA_URL=http://localhost:11434 \
BATCH_INTERVAL=30 \
python3 agent.py
```

You will be prompted for your name and a 6-character session code. The agent will block at "Standby — waiting for session..." until the Red Team backend activates the session.

**Step 2 — Trigger event types by running the appropriate commands in a second terminal**

```bash
# investigation_started — examine a log file or alert
cat /var/log/syslog | grep -i "xss"
less /var/log/nginx/access.log

# incident_confirmed — confirm you are looking at a real attack
cat /var/log/nginx/access.log | grep "<script>"

# evidence_preserved — archive or hash artifacts
cp -r /var/log/nginx /tmp/evidence_nginx_$(date +%s)
sha256sum /var/log/nginx/access.log > /tmp/evidence.sha256
tar -czf /tmp/evidence.tar.gz /var/log/nginx/

# containment_initiated — block/kill/isolate
sudo iptables -I INPUT -s 192.168.1.100 -j DROP
sudo pkill -f "malicious_process"

# containment_succeeded — verify containment is active
sudo iptables -L INPUT | grep DROP

# eradication_completed — remove malicious artifacts
sudo rm -f /var/www/html/shell.php
sudo userdel backdoor_user
sudo systemctl disable malicious-service

# recovery_validated — health check that service is restored
curl -s http://localhost:80/health
systemctl status nginx
ping -c 3 8.8.8.8
```

Wait up to 30 seconds after each batch for the watcher to flush. Adjust `BATCH_INTERVAL` to a smaller value (e.g. 10) during testing.

**Step 3 — Verify classification in watcher stdout**

```
2026-06-23 10:00:30 [INFO] [watcher] classifying 5 command(s) with Ollama
2026-06-23 10:00:32 [INFO] [blueteam] posted event_type=evidence_preserved  t_offset=142s
```

If Ollama returns `{"events": []}` the commands in that batch were not recognized as SOC actions — run more unambiguous commands and wait for the next flush.

**Step 4 — Verify events stored in the Blue Team API**

```bash
# Replace INCIDENT_ID with the one printed at watcher startup
curl -s http://<host>:8010/blueteam/analyst-actions/INCIDENT_ID | python3 -m json.tool
```

Expected response:

```json
{
  "incident_id": "wazuh-1782165271.6613",
  "count": 3,
  "actions": [
    {
      "analyst_id": "analyst-alice",
      "incident_id": "wazuh-1782165271.6613",
      "scenario_id": "APP-01",
      "event_type": "evidence_preserved",
      "t_offset_sec": 142,
      "detail": "Analyst archived Nginx logs to /tmp/evidence directory",
      "timestamp": 1718001234.567,
      "stored_at": 1718001235.1
    }
  ]
}
```

**Step 5 — Verify the JSONL file on disk**

```bash
docker exec attense_app cat /attense/actions/analyst-alice_$(date +%Y-%m-%d).jsonl
```

Each line is one JSON object. The file is append-only.

**Step 6 — Inject a test event directly via curl (no auditd required)**

Useful when you do not have a Linux machine with auditd, or want to force a specific event type for pipeline testing:

```bash
curl -s -X POST http://<host>:8010/blueteam/analyst-action \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_id":   "analyst-testuser",
    "incident_id":  "wazuh-1782165271.6613",
    "scenario_id":  "APP-01",
    "event_type":   "evidence_preserved",
    "t_offset_sec": 90,
    "detail":       "Manual test: archived nginx logs to /tmp/evidence",
    "timestamp":    1718001234.0
  }'
```

Valid `event_type` values for this endpoint (all 11 from `AnalystEventType` enum):

```
investigation_started   incident_confirmed      containment_initiated
containment_succeeded   incident_ended          alert_denied
evidence_preserved      eradication_completed   recovery_validated
dismissal_approved      lessons_learned_recorded
```

---
---

## REPORT PIPELINE

### What it does

After an incident is over (or at any point for testing), the report pipeline reads all events for a given `incident_id` — combining what Wazuh/signal-store detected with what the analyst actually did — builds a complete picture of the response, evaluates it against 9 structured rules, computes a numeric score and verdict, and sends everything to Gemini to produce a formal 7-section markdown incident report. The report is written to `/attense/actions/<incident_id>_report.md` and printed to stdout.

---

### Data flow

```
run_pipeline.py: main(incident_id)
    │
    ▼
bridge.py: run_bridge(incident_id)
    │
    ├─ _load_wazuh_events(incident_id)
    │     reads /attense/data/mapped_events.jsonl  (signal-store output)
    │     filters lines where incident_id matches
    │     builds Event objects: actor_type="system"
    │     (event types: alert_raised, malicious_action_executed, etc.)
    │
    ├─ _load_analyst_events(incident_id)
    │     reads /attense/actions/analyst-*.jsonl   (watcher + TheHive events)
    │     filters lines where incident_id matches
    │     maps watcher names to canonical ATTENSE names:
    │       "investigation_started" → "alert_investigation_started"
    │       all others are already canonical (identity mapping)
    │     builds Event objects: actor_type="blue_team"
    │
    ├─ merges + sorts all events by timestamp
    │  builds Incident object, calls incident.apply_event() for each
    │
    ├─ report.py: generate_report(incident)
    │     TTD = time from start_time to detection_time  (timedelta or None)
    │     TTC = time from start_time to containment_time (timedelta or None)
    │     outcome = classify_outcome(incident)  — priority chain, checked in order:
    │       FALSE_POSITIVE → alert_raised event present AND incident.start_time is None
    │       FAILURE        → status == ENDED AND detection_time is None
    │       PARTIAL        → status == ENDED AND containment_time is None
    │       SUCCESS        → status == ENDED (detection_time and containment_time both set)
    │       INCOMPLETE     → status is anything other than ENDED
    │     Note: FALSE_POSITIVE is evaluated first, before the status match.
    │     FAILURE means the attack ended without ever being detected.
    │     returns 10-key dict: {incident_id, scenario_id, status, start_time,
    │                           detection_time, containment_time, end_time,
    │                           ttd, ttc, outcome}
    │
    ├─ scoring_engine.py: score_incident(incident, events, rule_data)
    │     locates the matching scenario block in the rule JSON
    │     builds event index: first-occurrence offset per event_type (seconds from t0)
    │     t0 = timestamp of first alert_raised event
    │     evaluates 9 rules (see table below)
    │     computes final_score, verdict, penalty_total, ttc_factor, difficulty_bonus
    │     returns ScoringResult with per-rule status + evidence strings
    │
    │  [live incidents only — no fixture scenario block matches]
    │  live_thresholds.py: compute_live_thresholds(scenario_id)
    │     returns ttc_expected_sec, ttc_max_sec, mtta_threshold_sec
    │     bridge.py builds a synthetic scenario block from these + alert_raised severity
    │
    ▼
report_generator.py: generate(report_dict, events)
    │  formats Gemini prompt (see full prompt below)
    │  calls Vertex AI: genai.Client(vertexai=True, project=..., location=...)
    │                        .models.generate_content(model="gemini-3.5-flash", ...)
    │  falls back to plain-text formatter if Gemini call fails
    │
    ▼
writes to: /attense/actions/<incident_id>_report.md
prints to: stdout
```

---

### The 9 scoring rules

All penalties are applied at once (not cascading). R03, R06, R07, R08 are **conditional** — each fires only if its prerequisite event is present.

| Rule | Penalty | What triggers it |
|---|---|---|
| R01 | −15 pts | `alert_investigation_started` absent, OR present but after `mtta_threshold_sec` |
| R02 | −15 pts | Neither `incident_confirmed` nor `dismissal_approved` present |
| R03 | −10 pts | `incident_confirmed` present, but `evidence_preserved` absent OR after `containment_initiated` |
| R04 | −25 pts | `containment_initiated` absent, OR present but after `ttc_max_sec` |
| R05 | −30 pts | `containment_succeeded` absent |
| R06 | −10 pts | `containment_succeeded` present, but `eradication_completed` absent OR before it |
| R07 | −10 pts | `eradication_completed` present, but `recovery_validated` absent OR before it |
| R08 | −5 pts | `recovery_validated` present, but `lessons_learned_recorded` absent OR before it |
| R09 | −20 pts | `alert_denied` present for severity medium/high/very_high without a preceding `dismissal_approved` |

**Scoring formula:**

```
ttc_factor = 1.0   if containment_succeeded ≤ ttc_expected_sec
           = linear decay (ttc_max − actual) / (ttc_max − ttc_expected)
                   between ttc_expected and ttc_max
           = 0.0   if containment_succeeded absent, or after ttc_max

difficulty_bonus = min(4500 × difficulty_numeric / max(investigation_delay_sec, 1), 25)
                   only applied when containment_succeeded is present
                   difficulty_numeric: low=1, medium=2, high=3, very_high=4

final_score = clamp(round((100 + penalty_total) × ttc_factor + difficulty_bonus, 2), 0, 100)
```

**Verdict bands:** excellent (90–100) · acceptable (70–89.99) · needs_review (50–69.99) · failed (0–49.99)

**Live incident thresholds** (used when no fixture scenario matches — i.e. every real attack):

| Attack type | CVSS | Difficulty | ttc_expected | ttc_max | mtta_threshold |
|---|---|---|---|---|---|
| APP-01 XSS | 7.6 | low | 8640s (2.4h) | 12960s | 600s |
| APP-02 CMDI | 9.8 | medium | 900s (15m) * | 1350s | 750s |
| APP-03 DIR | 7.5 | low | 9000s (2.5h) | 13500s | 600s |
| APP-04 FUP | 8.8 | medium | 4320s (1.2h) | 6480s | 750s |
| APP-05 CSRF | 6.5 | medium | 12600s (3.5h) | 18900s | 750s |
| APP-06 BA | 8.2 | low | 6480s (1.8h) | 9720s | 600s |

\* APP-02 CMDI shows `ttc_expected=900s` rather than the raw formula result of 720s because 900s is the formula's floor (`max(900, ...)`). CMDI's CVSS of 9.8 would otherwise produce an unrealistically short 720-second containment window.

---

### The Gemini prompt (full, current)

This is the exact prompt string built in `attense-app/pipeline/report_generator.py`. Bracketed tokens are substituted at runtime from the report dict and event list.

```
You are a senior SOC analyst writing a formal incident response report in markdown.
Use the structured data below. Output ONLY the markdown — no commentary before or after.

---
Incident ID:   {incident_id}
Scenario ID:   {scenario_id}
Final Status:  {status}
Outcome:       {outcome} — {outcome_explanation}

Time to Detect (TTD):  {ttd}
Time to Contain (TTC): {ttc}

Score:         {final_score} / 100
Verdict:       {verdict}
Penalty Total: {penalty_total} pts

Attack Context (cite verbatim — do not elaborate beyond what is written here):
  MITRE ATT&CK Primary:  {technique_id} — {technique_name} ({tactic})
  MITRE ATT&CK Related:  ...
  ATT&CK Mapping Note:   {mapping_note}
  Response Framework:    {framework_name}
  Framework Note:        {framework_note}

Rule Breakdown (9 rules — [PASS] passed | [FAIL] triggered, penalty shown | [N/A ] not applicable):
  [FAIL] XSS-R01  Alert triage must be initiated within MTTA threshold  (-15 pts)
         Evidence: alert_investigation_started at t=890s exceeded mtta_threshold=600s (late by 290s)

  [PASS] XSS-R02  Incident must be confirmed or formally dismissed
         Evidence: incident_confirmed at t=120s

  [N/A ] XSS-R03  Evidence must be preserved before destructive containment
         Evidence: incident_confirmed absent — rule does not apply
  ...

Analyst Actions (chronological):
- 10:00:30 (t=+30s)  **analyst-alice**  →  investigation_started  |  Examined Wazuh alert for XSS rule 31106
- 10:02:00 (t=+120s) **analyst-alice**  →  incident_confirmed     |  Confirmed XSS attack from 172.21.0.1
---

Write a markdown report with these exact sections:

1. `# Incident Report: {incident_id}`

2. `## Summary` — 2-3 sentences: what attack type occurred, how the team responded,
   and what the final score ({final_score}/100, verdict: {verdict}) reflects about
   their performance.

3. `## Timeline` — bullet list of analyst actions in plain English (who did what, when).

4. `## Metrics` — markdown table with columns Metric / Value, rows: TTD, TTC,
   Outcome, Score, Verdict, Penalty.

5. `## Score Breakdown` — for each [FAIL] rule: one bullet explaining in plain English
   what the rule required, what the evidence shows happened (or did not happen), and
   how many points it cost. If there are no [FAIL] rules, write a single sentence
   confirming the response was clean. Do not mention [N/A ] rules here.

6. `## Attack Context` — one short paragraph citing the ATT&CK techniques and response
   framework VERBATIM from the Attack Context block above. Copy technique IDs, names,
   and notes exactly as written. Do NOT add interpretation, external knowledge, or
   detail beyond what appears in ATT&CK Mapping Note and Framework Note above.

7. `## Assessment` — one paragraph that narrates and explains the computed result.
   Reference specific rule IDs (e.g. "R02 was triggered because...") to justify the
   score. Do NOT form an independent judgment of the response quality — your role is
   to translate the rule engine's output into plain English. A high score means explain
   why the rules passed; a low score means explain what the triggered rules reveal
   about the response gaps.
```

If Gemini fails for any reason (missing credentials, quota, network error), the pipeline falls back to a plain-text formatter that outputs the same sections without LLM assistance. The pipeline will always complete — it never exits on a Gemini error.

---

### Where the report ends up

```
/attense/actions/<incident_id>_report.md
```

Example: `/attense/actions/wazuh-1782165271.6613_report.md`

Also printed to stdout in full during the pipeline run.

---

### Manual test: step by step

**Option A — Test against a real incident from a previous live run**

```bash
# 1. Get an incident_id from the signal-store
curl -s "http://localhost:8005/events?limit=5"
# copy any incident_id field, e.g. "wazuh-1782165271.6613"

# 2. Inject at least one analyst action for that incident
curl -s -X POST http://localhost:8010/blueteam/analyst-action \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_id":   "analyst-testuser",
    "incident_id":  "wazuh-1782165271.6613",
    "scenario_id":  "APP-01",
    "event_type":   "investigation_started",
    "t_offset_sec": 30,
    "detail":       "Examined Wazuh alert for XSS rule 31106",
    "timestamp":    1718001230.0
  }'

# 3. Run the pipeline inside the attense_app container
docker exec -it attense_app bash
export VERTEX_PROJECT_ID=your-gcp-project-id
export VERTEX_MODEL=gemini-3.5-flash
export VERTEX_LOCATION=global
python3 -m pipeline.run_pipeline wazuh-1782165271.6613
```

**Option B — Fully self-contained test with injected events (no live Wazuh run needed)**

```bash
# Inject a fake alert_raised event into mapped_events.jsonl
docker exec attense_app bash -c "echo '{
  \"event_id\":\"test-001\",
  \"incident_id\":\"test-incident-001\",
  \"scenario_id\":\"APP-01\",
  \"actor_id\":\"wazuh\",
  \"target_id\":\"sandbox-target\",
  \"event_type\":\"alert_raised\",
  \"actor_type\":\"system\",
  \"target_type\":\"alert\",
  \"timestamp\":\"2026-06-23T10:00:00\",
  \"outcome\":\"detected\",
  \"metadata\":{\"wazuh_rule_id\":\"31106\",\"source_ip\":\"172.21.0.1\",\"severity\":\"high\"}
}' >> /attense/data/mapped_events.jsonl"

# Inject analyst actions via the API
INCIDENT=test-incident-001
T=0
for event_type in investigation_started incident_confirmed evidence_preserved \
                  containment_initiated containment_succeeded \
                  eradication_completed recovery_validated; do
  T=$((T + 60))
  curl -s -X POST http://localhost:8010/blueteam/analyst-action \
    -H "Content-Type: application/json" \
    -d "{
      \"analyst_id\":   \"analyst-testuser\",
      \"incident_id\":  \"${INCIDENT}\",
      \"scenario_id\":  \"APP-01\",
      \"event_type\":   \"${event_type}\",
      \"t_offset_sec\": ${T},
      \"detail\":       \"Test: ${event_type}\",
      \"timestamp\":    $(($(date +%s) + T)).0
    }" > /dev/null
  echo "injected: ${event_type} at t=+${T}s"
done

# Run the pipeline
docker exec -it attense_app bash
export VERTEX_PROJECT_ID=your-gcp-project-id
export VERTEX_MODEL=gemini-3.5-flash
python3 -m pipeline.run_pipeline test-incident-001

# Read the output file
docker exec attense_app cat /attense/actions/test-incident-001_report.md
```

**What to expect at each stage:**

```
=================================================================
  ATTENSE EVALUATION PIPELINE  |  test-incident-001
=================================================================

  [1/3] Loading events and building incident model...
        8 events loaded  (1 Wazuh / 7 analyst)
        Outcome: INCOMPLETE  |  Status: CONTAINED

  [2/3] Generating markdown report via Gemini...

  [3/3] Writing report → /attense/actions/test-incident-001_report.md

=================================================================
  REPORT
=================================================================

# Incident Report: test-incident-001
...
```

**Check Gemini credentials before running:**

```bash
# On the host machine
gcloud auth application-default login
gcloud auth application-default print-access-token   # should print a token, not an error
```

If `VERTEX_PROJECT_ID` is not set, the pipeline exits immediately with a clear list of what is missing before doing any work. If Gemini returns an error (403, quota, network), it logs the error and falls back to the plain-text report automatically.
