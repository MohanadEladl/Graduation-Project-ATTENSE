# Session Log — Red-Team Module Rework (MITRE ATT&CK) + Modules Card Redesign

**Date:** 2026-06-19
**Branch:** `feature/attacker-activity-log`
**Scope:** Red-team frontend module cards (HTB style) + full rework of the 7 attack modules to follow real, MITRE ATT&CK–mapped kill-chains, surfaced in the UI/API and validated against the live target.

---

## 1. Request 1 — Modules cards like Hack The Box

> "in the red team i want the modules cards in the frontend to be like this shape in hack the box"

### What changed
`red-team/frontend/src/routes/Modules.jsx` — redesigned the module cards to match the HTB layout:

- **Cover/illustration area** (16:10) with a circuit-grid background and a large, glowing category icon centered (scales up on hover, grid brightens).
- **Status badge** top-left of the cover (shows difficulty, severity-tinted) — mirrors HTB's "In Progress" chip.
- **Tag row** below the cover with small icon+label tags (`LAB`, category) in the accent color — like HTB's `REGULAR · GENERAL`.
- **Bold title** + scenario id.
- **Footer meta row** divided by `|` separators: difficulty, step count, tier, with a chevron that slides on hover — like HTB's `Fundamental | 30 min | Tier 0 >`.
- Whole card is one clickable button → navigates to the mission. Grid narrowed (~290px min) for HTB's denser 4-up layout.
- Severity drives accent color + difficulty/tier labels via two small maps.

---

## 2. Request 2 — Rework each module per MITRE ATT&CK with real commands

> "we will change how each module work ... according to mitre attack ... how each step is really made starting from reconnaissance ... real not too complicated and not too easy commands really made now ... then test each module according to mitre attacks"

### Investigation (crawling the target attack surface)
The deployed red-team backend is `./red-team` (not the nested `red-team/red-team/` duplicate). Modules run **real HTTP attacks** against `target-agent` and expose `steps` + `lab` metadata via `/api/modules`, rendered in `Mission.jsx` → `TaskAccordion.jsx`.

Real, intentionally-vulnerable endpoints on the target (`target-agent/app/routes/`):

| Endpoint | Vuln | Module |
|---|---|---|
| `GET /search?q=` | Reflected XSS (`q\|safe`) | xss |
| `POST /auth/login` | No rate limit, username enumeration, weak creds | brute_force |
| `GET /system/ping?host=` | Command injection (`os.popen`) | cmd_injection |
| `GET /files/read?path=` | Path traversal (no normalization) | dir_traversal |
| `POST /files/upload` | Unrestricted upload (stored, not executed) | file_upload |
| `POST /profile/update` | CSRF (no token/Origin check) | csrf |
| `/` + all routes | Recon surface | recon |

### Changes per module (`red-team/modules/*.py`)
For **recon, xss, brute_force, cmd_injection, dir_traversal, file_upload, csrf**:

1. Added a `mitre` class attribute — `tactics` + `techniques` (technique IDs + names + tactic).
2. Rewrote `lab.learner_steps` and engine `steps` so **every step carries a tactic + technique + a real `curl` command**, beginning with a recon/baseline step then escalating. Existing progress `markers` were preserved.
3. Made each `execute()` **start with a genuine recon/baseline request** (additive `StepResult`, doesn't disturb markers).
4. **Bug fix (csrf):** forged `Origin`/`Referer` headers were set *after* the request — moved them onto the forged POST so the cross-origin CSRF is realistic and triggers the lure evidence.

#### MITRE mapping summary
| Module | Tactics | Techniques |
|---|---|---|
| recon | Reconnaissance | T1595.002, T1595.003, T1592.002 |
| xss | Reconnaissance, Execution | T1595.002 → T1059.007 → T1189 |
| brute_force | Reconnaissance, Credential Access | T1589.001 → T1110.001 / T1110.004 |
| cmd_injection | Initial Access, Execution, Discovery | T1190 → T1059.004 → T1033 |
| dir_traversal | Initial Access, Discovery, Credential Access | T1190 → T1083 → T1552.001 |
| file_upload | Initial Access, Persistence | T1190 → T1505.003 |
| csrf | Initial Access, Impact | T1078 → T1204.001 → T1565.001 |

### Surfacing (API + UI)
- `red-team/backend/main.py` — `/api/modules` now serializes the `mitre` field.
- `red-team/frontend/src/routes/Mission.jsx` — Mission hero shows clickable MITRE ATT&CK technique chips (link to attack.mitre.org); passes `command`/`technique` into the accordion.
- `red-team/frontend/src/components/TaskAccordion.jsx` — each task shows a technique tag, a `MITRE TECHNIQUE` line, and a `COMMAND` code block.

---

## 3. Testing against the live target

Brought up a partial stack (`target-agent`, `red-team-backend`, `attackbox`) and ran every module's real chain via the backend against `target-agent`.

### Results — all passed
| Module | MITRE | Result |
|---|---|---|
| recon | T1595.002/.003, T1592.002 | 8/8 endpoints probed |
| xss | T1595.002 → T1059.007 → T1189 | 5/5 payloads reflected |
| brute_force | T1589.001 → T1110.001/.004 | found admin:password123, operator:lab2024, guest:guest |
| cmd_injection | T1190 → T1059.004 → T1033 | 5/5 RCE confirmed |
| dir_traversal | T1190 → T1083 → T1552.001 | 3/5 disclosed (passwd/environ; shadow correctly denied) |
| file_upload | T1190 → T1505.003 | 4/4 web-shell extensions accepted |
| csrf | T1078 → T1204.001 → T1565.001 | 2/2 forged state changes |

API verified serving `mitre` + per-step commands + learner command/technique for all 7 modules.

---

## 4. Environment gotchas discovered (important for next session)

- **Docker only works through the PowerShell tool.** The Bash tool's sandbox sees an empty docker context (no containers) even though `docker version` reports a server.
- **PowerShell CWD is `...\attense-v6\red-team`, NOT the repo root**, and there is an untracked nested duplicate `red-team/red-team/`. Relative paths like `red-team/modules/x.py` in PowerShell hit the **stale nested copy** — `docker cp` then copies the wrong file. Use paths relative to `red-team/` (e.g. `modules/x.py`) or absolute. (The Bash tool's CWD is the repo root.)
- **Partial-stack testing must include `attackbox`.** target-agent's `detect_via()` calls `socket.getaddrinfo("attackbox")` on every request while its IP cache is empty; without attackbox running each request stalls ~5–15s on DNS timeout (caused XSS/cmd-i to time out at the 10s `TargetConfig.timeout` and falsely report 0 hits). With attackbox up, responses drop to ~4ms.
- **target-agent entrypoint waits ~120s for Wazuh** (`wazuh.manager:1515`) then starts Flask anyway — it serves even without wazuh-manager.
- **Validation harness:** import each `modules.*` class, call `execute(TargetConfig(host="target-agent",port=80), opts)`, redirect output to a file in the container and `cat` it (the PowerShell background-task output file does not reliably flush python stdout).

---

## 5. Deployment status / follow-ups

- **Backend** is live-patched via `docker cp` + restart (no volume mounts). Updated files deployed: all 7 `modules/*.py` + `backend/main.py`.
- **Frontend** changes (Mission/TaskAccordion + Modules card redesign) need a **frontend image rebuild** to show on port 3000, or `npm run dev` (port 5173).
- Full stack (Wazuh, signal-store, TheHive, Cortex, etc.) was **down** during testing — bring back with `docker compose up -d`.

### Files touched
```
red-team/frontend/src/routes/Modules.jsx          (HTB card redesign)
red-team/frontend/src/routes/Mission.jsx          (MITRE chips + pass command/technique)
red-team/frontend/src/components/TaskAccordion.jsx (technique tag + command block)
red-team/backend/main.py                          (serialize mitre)
red-team/modules/recon.py
red-team/modules/xss.py
red-team/modules/brute_force.py
red-team/modules/cmd_injection.py
red-team/modules/dir_traversal.py
red-team/modules/file_upload.py
red-team/modules/csrf.py
```
