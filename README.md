# ATTENSE v6 — Guided Red Team Cyber Lab

A hands-on, guided cybersecurity education platform where learners explore
real vulnerabilities in a safe, local-only lab environment.

---

## What is ATTENSE?

ATTENSE is an interactive cyber range designed for learning offensive security
concepts through hands-on practice. Instead of running automated attacks,
learners manually interact with a purposefully vulnerable web application,
observe evidence of their actions, and learn both offensive techniques and
defensive countermeasures.

ATTENSE follows a TryHackMe-style guided approach:
- Read the mission briefing.
- Interact with the vulnerable target application.
- Observe evidence and detection events.
- Understand how to defend against each vulnerability.

## ⚠️ Local-Only Safety Note

ATTENSE runs **entirely inside Docker containers** on your local machine.
All interactions target a local vulnerable application (`target-agent`).
There is **no external attack capability** — all traffic stays within the
Docker network. This platform is for **educational purposes only**.

---

## Architecture Overview

```
Browser (localhost:3000)
  │  HTTP
  ▼
red-team-frontend   (React + Vite, nginx)
  │  proxies /api → red-team-backend
  │  proxies /target → target-agent
  ▼
red-team-backend    (FastAPI — session management + progress engine)
  │  checks evidence from target-agent
  ▼
target-agent        (Flask — purposefully vulnerable web app)
  │  logs evidence events to internal store
  ▼
signal-store → attense-app  (detection pipeline + dashboard)
```

### Key Components

| Component | Role |
|---|---|
| **React Frontend** | Mission dashboard, Lab Browser (iframe), Learning Panel |
| **Lab Browser** | Embedded iframe showing the vulnerable target at `/target/...` |
| **target-agent** | Vulnerable Flask app with 7 attack surfaces (login, search, ping, files, upload, profile, CSRF lure) |
| **Evidence System** | target-agent records learner actions as evidence events; backend computes progress |
| **Guided Mode** | Step-by-step learner instructions with hints, evidence cards, and defensive insights |
| **Operator Mode** | Advanced interface with Terminal and ZAP panel placeholders for experienced users |

---

## How to Run

```bash
docker compose up --build
```

Open your browser:
- **ATTENSE Platform** → http://localhost:3000
- **Target App (direct)** → http://localhost:8080
- **Backend API** → http://localhost:8000/api/modules

---

## How to Use

1. **Choose a Module** — From the dashboard, select one of the 7 lab modules.
2. **Read the Briefing** — Each module has a background story, objective, and step-by-step instructions.
3. **Start the Mission** — Click **START** to load the vulnerable target in the Lab Browser.
4. **Guided Mode (default)** — Follow the learner steps in the sidebar. Interact with the target app manually.
5. **Interact with the Lab Browser** — Type in forms, submit payloads, explore pages — your actions generate evidence.
6. **Switch to Operator Mode (optional)** — For advanced users. Enables Terminal and ZAP panel placeholders.
7. **Check Progress** — Click **CHECK PROGRESS** to see which tasks you've completed and what evidence was collected.
8. **Review Evidence and Defenses** — Evidence cards appear in real time. After completing a mission, review the defensive insight to learn how to prevent each vulnerability.

---

## Module List and Target Pages

| Module | Scenario | Severity | Target Path | Description |
|---|---|---|---|---|
| `recon` | PRE-ATTACK | INFO | `/` | Map the attack surface by exploring the portal |
| `brute_force` | APP-06 | HIGH | `/auth/login` | Discover credentials via brute force on unprotected login |
| `xss` | APP-01 | HIGH | `/search` | Confirm reflected XSS on the search page |
| `cmd_injection` | APP-02 | CRITICAL | `/system/ping` | Inject OS commands via the ping diagnostics form |
| `dir_traversal` | APP-03 | HIGH | `/files/read` | Read arbitrary files via path traversal |
| `file_upload` | APP-04 | HIGH | `/files/upload` | Upload files with dangerous extensions (stored, not executed) |
| `csrf` | APP-05 | MEDIUM | `/profile/` and `/evil/csrf-demo` | Demonstrate CSRF via the built-in attacker lure page |

---

## Evidence and Check Progress

Each vulnerable endpoint in `target-agent` records **evidence events** when the
learner interacts with it. Examples:
- `login_failed`, `brute_force_pattern`, `credential_found`
- `xss_payload_observed`, `reflected_input_detected`
- `command_separator_observed`, `command_injection_detected`
- `traversal_pattern_observed`, `sensitive_file_disclosed`
- `dangerous_extension_accepted`, `unrestricted_upload_detected`
- `csrf_lure_visited`, `csrf_lure_submitted`, `profile_changed_without_csrf`

Clicking **CHECK PROGRESS** in the Workspace fetches these events and matches
them against per-module success criteria. Progress auto-polls every 8 seconds
while a mission is active.

---

## Operator Mode

Operator Mode is an advanced interface for experienced security professionals.
When activated, two tool panels become available below the Lab Browser, each
backed by a real container — they are no longer placeholders.

### Terminal — ATTENSE AttackBox (real)

A live shell into the local `attackbox` container, with live status polling
every 15 seconds.

- Preinstalled tools: `nmap`, `hydra`, `curl`, `ffuf`, `gobuster`, `jq`,
  `python3`, `nc`
- Wordlists at `/wordlists/` (also symlinked to `/opt/wordlists/`):
  `passwords-small.txt`, `users.txt`, `routes.txt`, `xss-payloads-small.txt`
- Kali system wordlists at `/usr/share/wordlists/` (e.g. `dirb/common.txt`)
- Commands run inside the AttackBox container and are executed via the
  backend at `/api/attackbox/exec`
- Output is streamed back into the terminal with proper color coding
  (output / error / dim / blocked)
- Status badge reflects the AttackBox container state
  (`running` / `stopped` / `offline` / `error`)
- Up/Down arrow command history (last 50 commands), `Ctrl+L` to clear
- **External targets are blocked** — only the local `target-agent` is
  reachable. Blocked attempts return a `⛔` line in the terminal.

### ZAP — OWASP ZAP local proxy (real)

A live connection to the local OWASP ZAP container with three working tabs:

- **Proxy History** — Polls `/api/zap/history` every 8 seconds. Shows the
  last 50 captured requests with method, URL, and response code (color-coded
  by 2xx / 4xx / 5xx).
- **Request Inspector** — Click any request in Proxy History to inspect
  method, URL, status code, and response size in detail.
- **Repeater** — Re-issue or hand-craft requests against `target-agent`:
  pick a method (`GET / POST / PUT / DELETE / PATCH / HEAD / OPTIONS`),
  edit the path (host is locked to `http://target-agent`), provide an
  optional body, and view the JSON response inline.

If the ZAP container is not running, the panel shows a friendly offline
message with the start command.

### Evidence gating — operator mode requires AttackBox traffic

Every request to `target-agent` is classified by `detect_via()` based on
its headers and tagged onto the resulting evidence event:

| Signal | Classification |
|---|---|
| `User-Agent` contains `AttenseAttackBox` | `via=attackbox` |
| `User-Agent` contains `AttenseZAPRepeater` | `via=zap_repeater` |
| `User-Agent` contains `AttenseZAPFuzzer` | `via=zap_fuzzer` |
| Request comes from the AttackBox container's IP | `via=attackbox` |
| `X-Forwarded-Prefix: /target` (set by the lab-browser proxy) | `via=browser` |
| Anything else | `via=unknown` |

The progress engine (`backend/lab_progress.py::compute(mode=...)`) uses
this:

- **Guided mode** counts evidence from any channel — clicking around the
  iframe drives the ladder.
- **Operator mode** *only* counts evidence with `via=attackbox`,
  `via=zap_repeater`, or `via=zap_fuzzer`. Each
  module also has a stricter `tasks_operator` ladder (e.g. brute_force
  requires 6+ failed logins from the terminal, not 3). Browser clicks
  during operator mode appear as evidence cards (so the learner can see
  what they did) but are explicitly marked `counts=false`.

The lab-browser iframe is also visually locked while operator mode is
active: `pointer-events: none`, a grayscale/dim filter, and an overlay
that says "Use the Terminal or ZAP to drive this attack."

The AttackBox container's `Dockerfile` injects the User-Agent header into
every outbound HTTP request via `/etc/curlrc`, environment variables, and
shell aliases for `curl` / `wget` / `gobuster` — so any command the
learner pastes from the operator step cards is already correctly tagged.

End-to-end proof:

```
python scripts/verify_operator_gating.py
```

This drives 8 failed + 1 successful login through the brute_force flow
twice — once with browser headers, once with AttackBox headers — and
asserts that operator-mode progress stays at 0% in the first case and
reaches 100% in the second.

### Hint → Command toggle

Each operator step has its hint and goal visible up front, but the actual
command(s) for the step are hidden behind a `▾ SHOW COMMAND` button. Click
to reveal the command (with a `COPY` button), click again to hide it. This
encourages learners to think through the hint before peeking. The same
toggle covers both AttackBox terminal commands and ZAP repeater commands.

Guided Mode remains the default and recommended mode for learners; Operator
Mode is for users who already know what they're doing and want raw tool
access scoped to the lab.

---

## AI Report Agent (Free — Ollama)

The post-mission coaching report is generated by **Ollama**, running as a local
Docker container — no API key, no cost, and fully offline after the first model pull.

| Detail | Value |
|---|---|
| Service | `ollama` container on the internal `attense_net` network |
| Default model | `llama3.2:3b` (~2 GB download on first `docker compose up`) |
| Endpoint used | `POST http://ollama:11434/api/generate` |
| Fallback | Rules-based coaching fires automatically if Ollama is not reachable |

**First run:** `docker compose up --build` starts the Ollama container and the
`pull_ollama_model.sh` script pulls `llama3.2:3b` automatically. Subsequent
starts reuse the cached model from the `ollama_data` Docker volume.

**Change the model:** set `OLLAMA_MODEL` in the environment before starting:

```bash
OLLAMA_MODEL=mistral docker compose up
```

Any model available via `ollama pull` works. Larger models produce richer
coaching but require more RAM and take longer to generate (~10–60 s depending
on hardware).

**Offline use:** after the initial pull the model lives in the `ollama_data`
volume. The lab works fully air-gapped from that point on.

**Fallback:** if the Ollama container is not running or the model has not been
pulled yet, `report_agent.py` automatically falls back to the rules-based
coaching summary. The report badge shows `📋 COACHING SUMMARY` instead of
`🦙 OLLAMA`.

---

## Known Limitations

- **File upload** demonstrates unrestricted dangerous file upload only. Uploaded
  files are stored and served but **not executed** by Flask. This is not RCE.
- **Local lab only** — all targets are internal Docker containers. No external
  attack capability exists. The AttackBox terminal and ZAP repeater both
  reject any host other than `target-agent`.
- **Single-user** — the platform is designed for individual learning, not
  multi-user deployment.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Frontend shows stale UI | Run `docker compose up --build` to rebuild the frontend container |
| `/target` pages return 502 | Ensure `target-agent` container is running: `docker compose ps` |
| Evidence not updating | Hard refresh the browser (Ctrl+Shift+R) and click CHECK PROGRESS |
| Port conflict on 3000 | Change the port mapping in `docker-compose.yml` |
| Module not found error | Restart the backend: `docker compose restart red-team-backend` |

---

---

## v8 Features — Skill Graph · Attack Chains · Mutation Mode

Three advanced training features shipped in v8:

| # | Feature | Location |
|---|---|---|
| 1 | **Skill Graph** | Persistent per-learner radar chart on the Dashboard |
| 2 | **Attack Chains** | Multi-step missions at `/gauntlet` |
| 3 | **Mutation Mode** | Target behaviour changes mid-mission, visible in Workspace |

---

### Feature 1 — Skill Graph

**Files:** `red-team/backend/skill_store.py`, `red-team/frontend/src/components/SkillRadar.jsx`, `red-team/frontend/src/routes/Dashboard.jsx`

The skill graph tracks per-learner progress across all 7 modules × 3 variants (21 skill entries total). Data persists to `/data/skills.json` inside the backend container.

**How it works:**
- After completing any mission, call `POST /api/skills/update` with the session ID to record the score.
- The Dashboard fetches `GET /api/skills` and renders a pure-SVG radar chart (7 axes, concentric ring guides, framer-motion entrance animation).
- A recommendation card fetches `GET /api/skills/recommend` and highlights the weakest untrained variant with a "TRAIN THIS NOW →" button.

**Skill data shape per module/variant:**
```json
{
  "brute_force": {
    "password_spray": {
      "attempts": 2,
      "best_score": 87,
      "best_grade": "A",
      "last_played": 1718000000.0,
      "technique_scores": [62, 87]
    }
  }
}
```

**Backend endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/api/skills` | Returns radar data — one entry per module with avg score and variant breakdown |
| GET | `/api/skills/recommend` | Returns the weakest unplayed/low-scored variant |
| POST | `/api/skills/update` | Body `{ session_id }` — reads report cache, persists score to skill store |

---

### Feature 2 — Attack Chains

**Files:** `red-team/backend/chain_engine.py`, `red-team/frontend/src/routes/Gauntlet.jsx`

Attack chains are multi-step missions. Each step requires completing one module (score ≥ 60%) before the next unlocks. Evidence is reset between steps.

**Built-in chains:**

| Chain ID | Name | Steps |
|---|---|---|
| `full_compromise` | Full Compromise | recon → brute_force → xss → csrf |
| `root_the_box` | Root the Box | recon → cmd_injection → dir_traversal → file_upload |
| `data_exfiltration` | Data Exfiltration | recon → brute_force → dir_traversal → csrf |

**How it works:**
1. Go to **Gauntlet → Attack Chains** and click "Start Chain".
2. Complete the current step's module in the Lab Browser (regular mission flow).
3. Click "Check Step" to verify completion. When score ≥ 60%, click "Advance".
4. Evidence resets automatically between steps — you start fresh.
5. A chain report with aggregate score and grade is shown on completion.

**Backend endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/api/chains` | List all available chains |
| GET | `/api/chains/{chain_id}` | Full chain definition with steps |
| POST | `/api/chains/{chain_id}/start` | Create a chain session (`{ session_id }`) |
| GET | `/api/chain-sessions/{id}` | Get chain session state |
| POST | `/api/chain-sessions/{id}/check` | Check if current step is complete |
| POST | `/api/chain-sessions/{id}/advance` | Advance to next step (409 if not complete) |
| GET | `/api/chain-sessions/{id}/report` | Aggregate report with grade |

---

### Feature 3 — Mutation Mode

**Files:** `target-agent/app/mutation_engine.py`, `red-team/frontend/src/components/MutationBanner.jsx`, `red-team/backend/main.py` (proxy endpoints)

Mutations change the behaviour of vulnerable routes mid-mission. The learner must adapt their technique. All mutation logic is wrapped in `try/except` — if mutation_engine fails, the route continues normally (fail-open).

**Available mutations:**

| ID | Module | Effect | Learner Hint |
|---|---|---|---|
| `bf_delay` | brute_force | 2-second delay on every login attempt | Use a slower wordlist |
| `bf_lockout` | brute_force | Account locked after 5 failed attempts (60s) | Rotate target accounts, watch for 403 |
| `xss_encode` | xss | `<` and `>` encoded in output; event handlers still injectable | Use `onerror=`, `onload=` payloads |
| `xss_csp` | xss | CSP header blocks inline scripts | Look for script-src bypasses |
| `ci_filter_pipe` | cmd_injection | `\|` stripped from host input | Try `;`, backtick, `$()` |
| `ci_filter_semi` | cmd_injection | `;` stripped from host input | Try pipe or backtick injection |

**How mutations are triggered** (instructor/operator flow):
```bash
# Activate a mutation for a session
curl -X POST http://localhost:8000/api/sessions/{sid}/mutations/trigger \
  -H "Content-Type: application/json" \
  -d '{"module_id": "xss", "mutation_id": "xss_encode"}'

# Schedule a mutation to fire after a delay
curl -X POST http://localhost:8000/api/sessions/{sid}/mutations/schedule \
  -H "Content-Type: application/json" \
  -d '{"module_id": "cmd_injection", "mutation_id": "ci_filter_pipe", "delay_seconds": 30}'

# List active mutations for a session
curl http://localhost:8000/api/sessions/{sid}/mutations
```

**Workspace integration:** The Workspace polls `GET /api/sessions/{sid}/mutations` every 5 seconds. When a new mutation appears, a dismissible `MutationBanner` slides in showing the mutation label, description, and hint. The banner re-appears automatically if the mutation set changes (new IDs arrive).

**Backend proxy endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/api/sessions/{sid}/mutations/trigger` | Activate a mutation immediately |
| POST | `/api/sessions/{sid}/mutations/schedule` | Schedule mutation after `delay_seconds` |
| GET | `/api/sessions/{sid}/mutations` | List active mutations for a session |

**Target-agent control endpoints** (internal, called by backend):

| Method | Path | Description |
|---|---|---|
| GET | `/lab/mutations` | All available mutations |
| GET | `/lab/mutations/active?session_id=` | Active mutations for a session |
| POST | `/lab/mutations/set` | Activate `{ session_id, module_id, mutation_id }` |
| POST | `/lab/mutations/clear` | Deactivate `{ session_id, module_id }` |

---

## Project Layout

```
attense-v6/
├── red-team/
│   ├── backend/        FastAPI — sessions, progress, evidence,
│   │                   attackbox + zap operator APIs (operator_api.py, shell/)
│   ├── frontend/       React + Vite — Lab Browser, Mission UI,
│   │                   Operator Terminal + ZAP panels
│   ├── engine/         Session state machine
│   ├── core/           Base module + models
│   └── modules/        7 attack modules (recon, brute_force, xss, etc.)
├── target-agent/       Flask — purposefully vulnerable web app
├── attackbox/          AttackBox container (nmap, hydra, curl, ffuf, …) + wordlists
├── signal-store/       Detection pipeline
├── attense-app/        Dashboard / monitoring
├── wazuh-manager/      Wazuh integration
├── docker-compose.yml  Full stack orchestration
└── README.md           This file
```
