# ATTENSE v7 — Operator Mode Hardening

This release makes operator mode an actual lab — not just a UI label.

## What changed

### 1. Server-side `via` tagging
- `target-agent/app/evidence.py` — every event now carries `via`:
  - `"browser"`   — request had `X-Forwarded-Prefix: /target` (the lab-browser proxy)
  - `"attackbox"` — User-Agent contains `AttenseAttackBox` OR source IP is the AttackBox container
  - `"unknown"`   — anything else
- Synthesized events (`brute_force_pattern`, `recon_sequence_observed`)
  inherit `via` from the triggering event so operator-mode gating works on
  derived events too.
- `/lab/events` accepts `?via=` query parameter for filtering.
- All 6 vulnerable routes (auth, search, system, files, profile, home) pass
  `via=current_app.detect_via()` on every `evidence.record()` call.

### 2. Mode-aware progress engine
- `red-team/backend/lab_progress.py` — `compute()` accepts `mode` parameter:
  - `mode="guided"`   counts evidence from any channel
  - `mode="operator"` only counts evidence with `via="attackbox"`
- Each module now has BOTH `tasks` (guided) and `tasks_operator` (stricter):
  - **brute_force operator**: requires 6+ failed logins (vs 3 in guided)
  - **xss operator**: requires 2+ distinct XSS-shaped payloads
  - **recon operator**: requires 4+ endpoints visited from AttackBox
  - **dir_traversal operator**: requires 2+ traversal patterns submitted
  - **file_upload operator**: requires 2+ files saved
  - **csrf operator**: requires forging the POST via curl with cookies
- Each module has `success_event_types_operator` for stricter success.

### 3. Rich operator task data
- `red-team/frontend/src/data/missionBriefings.js` — `OPERATOR_STEPS_BY_MODULE`
  is now an array of structured task objects per module, with:
  - `title`, `goal`, `command` (or `commands[]`)
  - `expected` output snippet
  - `flags` list explaining each command-line flag
  - `hint` for common mistakes
  - `success_marker` showing which evidence event proves the step
- All 7 modules ship with 5–6 hands-on tasks each (curl / hydra / gobuster).

### 4. Operator step rendering
- `Workspace.jsx` OPERATOR STEPS panel renders rich cards:
  - Numbered task heading with green ✓ when its `success_marker` event fires
  - Goal sentence
  - Code block with [COPY] button for each command
  - Yellow-highlighted "EXPECTED OUTPUT" snippet
  - Purple-highlighted hint box
  - Cyan/green status line showing the success marker

### 5. Iframe lock in operator mode
- The LabBrowser iframe is now darkened, grayscaled and `pointer-events: none`
  when `mode === 'operator'`.
- A centered overlay tells the learner: "🔒 OPERATOR MODE — IFRAME LOCKED.
  Use the Terminal or ZAP to drive this attack. Browser interactions inside
  this iframe will not count as evidence."

### 6. AttackBox auto-tagging
- `attackbox/Dockerfile` now drops `/etc/curlrc` and `/etc/profile.d/attense-attackbox.sh`
  so every `curl`, `wget`, `gobuster` invocation from inside the container
  automatically sends `User-Agent: AttenseAttackBox/1.0`. The target-agent
  recognizes this and tags the resulting event with `via="attackbox"`.

### 7. API + state plumbing
- `red-team/frontend/src/api/client.js` — `checkProgress(sid, mode)` accepts mode
- `red-team/backend/main.py` — `POST /api/sessions/{sid}/check-progress?mode=…`
- Progress is re-fetched immediately when the user toggles mode, plus polls
  every 8s otherwise.

## What stays unchanged

- Guided mode (default) works exactly as in v6. No regression.
- TheHive, signal-store, blueteam — completely untouched.
- The 6 vulnerable Flask routes still emit the same 23 canonical event types.
- The CSRF lure page at `/evil/csrf-demo` still works.
- AttackBox tools (curl, nmap, hydra, ffuf, gobuster, jq, python3, nc) — same.

## Verified before shipping

- 129 Python files parse clean (`ast.parse`)
- 34 frontend JS/JSX files parse clean (esbuild)
- docker-compose.yml validates as YAML
- Live end-to-end test, all 7 modules:
  - Each module's operator mode succeeds when AttackBox traffic is present
  - Browser-only activity correctly does NOT satisfy operator mode
- Live end-to-end test, browser/attackbox distinction:
  - Browser mode: `via="browser"` ← X-Forwarded-Prefix header detected
  - AttackBox mode: `via="attackbox"` ← User-Agent header detected
  - Direct mode: `via="unknown"` ← neither signal present

## How to verify yourself

```bash
docker compose up --build -d
# Open http://localhost:3000 → Brute Force module → click GUIDED MODE
# Type admin/wrong a few times in the iframe → click CHECK PROGRESS
# Confirm guided progress advances.

# Now click OPERATOR MODE.
# The iframe greys out and locks.
# Open the Terminal panel inside the workspace.
# Run: hydra -L /lab/users.txt -P /wordlists/rockyou-mini.txt target-agent ...
# Click CHECK PROGRESS — operator-mode tasks now complete.
```

## Known limitations

- I cannot run `docker compose up --build` in my dev sandbox.
- I cannot visually QA the iframe overlay or the rich task cards in a browser.
- The AttackBox UA injection works for shell-launched commands. Programs that
  ignore /etc/curlrc and reset the User-Agent header (rare) might bypass
  detection. The container-IP fallback catches those cases too.
