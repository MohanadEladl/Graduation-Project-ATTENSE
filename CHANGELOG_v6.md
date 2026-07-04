# ATTENSE v6 — Educational Lab Rebuild

This release implements the full P0/P1 spec from `New_requirment.txt` v6.

---

## v6.2 — Post-Mission Report System + UX Polish

### Post-Mission Report System (new)

**Backend**

- New `red-team/backend/report_generator.py` — standalone module that
  produces a structured JSON report from a finished session:
  - Grade (S/A/B/C/F) computed from score: +40 success, +task_ratio×40,
    +evidence density up to 20, −10 penalty for lab mode when browser
    evidence exceeds attackbox evidence.
  - Per-module `_IDEAL_STEPS` (4-step walkthrough with command + rationale),
    `_VULN_EXPLAINED` (CVSS category, what/why/real-world), and
    `_DEFENSIVE_CONTROLS` (3–4 mitigations with implementation notes)
    for all 7 modules: recon, brute_force, xss, cmd_injection,
    dir_traversal, file_upload, csrf.
  - Returns sections: summary, what_you_did_right, what_you_missed,
    ideal_approach, vulnerability_explained, defensive_controls,
    evidence_timeline, task_results.
- `red-team/backend/session_manager.py` — added `report_cache: Optional[dict]`
  field to `SessionRecord` so generated reports are cached in-memory.
- `red-team/backend/main.py` — two new endpoints:
  - `GET  /api/sessions/{sid}/report` — returns cached report or generates
    one by fetching events from target-agent and calling report_generator.
  - `POST /api/sessions/{sid}/report/regenerate` — clears cache and
    re-generates.

**Frontend**

- New `red-team/frontend/src/routes/MissionReport.jsx` — full report page
  at `/report/:sid`:
  - Grade badge (56×56, glowing border) with colour config S=gold, A=cyan,
    B=green, C=amber, F=red.
  - 9 sections with framer-motion stagger fade-up animations: Header,
    Summary stats, Task Results, What You Did Right, What You Missed,
    Ideal Approach (copyable command blocks), Vulnerability Explained,
    Defensive Controls, Evidence Timeline.
  - REGENERATE REPORT and PRINT / EXPORT PDF actions at the bottom.
  - Print CSS: white background, hides nav/action buttons.
  - Loading spinner and error states.
- `red-team/frontend/src/App.jsx` — added `/report/:sid` route.
- `red-team/frontend/src/api/client.js` — added `sessions.getReport(sid)`
  and `sessions.regenReport(sid)`.

**Workspace integration**

- `Workspace.jsx` — on `progress.success`, pre-warms the report cache with
  `api.sessions.getReport(sid)` (fire-and-forget, result ignored).
- Slide-up completion banner appears after the report is ready:
  "MISSION COMPLETE" + "VIEW REPORT →" link to `/report/:sid`.
- `Dashboard.jsx` — REPORT button on mission cards now navigates to
  `/report/:sid` instead of `/mission/:sid`.

---

### UI / UX Improvements

- **Hint visibility** — "Reveal Hints" section is now hidden in Tutorial
  mode and shown only in Lab mode (`Workspace.jsx`: guard with `isLab`).
- **Module buttons on Dashboard** — clicking a module name card now
  navigates to `/mission/${id}` (mission detail page) instead of the
  broken `/modules/${id}` route.
- **Sidebar open/close animation** — `Sidebar.jsx` and `AppLayout.jsx` use
  framer-motion `AnimatePresence` + `motion.aside` / `motion.button` for
  smooth width and opacity transitions.
- **Auth branding** — `target-agent/app/routes/auth.py` `_LOGIN_PAGE`
  template changed from "ATTENSE PORTAL" to "Lab" (title, brand heading,
  back-link text).
- **Lab mode iframe** — removed "Target not available" overlay and the
  `pointerEvents: none` / grayscale filter that blocked the iframe in lab
  mode (`Workspace.jsx`).
- **Terminal minimize/maximize** — chevron toggle button added to
  `TerminalPanel.jsx` and `ZapPanel.jsx` headers; the lab panel container
  in `Workspace.jsx` animates height between 42 px (minimized) and 320 px.
- **Panel collapse/expand** — `MissionSidebar` (left, 280 px) and
  `LearningPanel` (right, 360 px) each have a toggle button; framer-motion
  animates the width to 36 px when collapsed.

## What's new

### P0 #1 — Iframe routing fixed
- `red-team/frontend/nginx.conf` proxies `/target/*` → `target-agent` and
  injects `X-Forwarded-Prefix: /target` so all forms/links/redirects in the
  vulnerable pages stay inside the iframe.
- `red-team/frontend/vite.config.js` does the same for dev mode.
- New `lab_url()` helper in `target-agent/app/main.py`. All 6 route files
  switched from python `.format()` placeholders to Jinja `{{ }}` variables
  so `{{ lab_url('/path') }}` works everywhere — forms, anchors, redirects,
  upload-result links.
- XSS reflection still works via Jinja's `|safe` filter.

### P0 #2 — Evidence + progress system
- New file `target-agent/app/evidence.py` — in-memory ring buffer of
  structured lab events. 23 canonical event types covering all 7 modules.
  Detects derived patterns (e.g. brute_force_pattern after 3 failed logins).
- Every vulnerable route emits `evidence.record()` with module_id, path,
  source_ip, severity, learner_message.
- `target-agent` exposes `GET /lab/events?since=&module_id=` and
  `POST /lab/events/reset` for the red-team backend to query.
- `red-team/backend/lab_progress.py` defines per-module success specs
  (3 tasks per module, success_event_types, defensive_insight) and
  computes evidence-driven progress.
- New `red-team/backend` endpoints:
  - `POST /api/sessions/{sid}/start` — sets mission_started_at + starts
    timer, **does NOT execute the attack**
  - `POST /api/sessions/{sid}/check-progress` — pure read of evidence
  - `POST /api/sessions/{sid}/reset-evidence` — clears events for replay
- `SessionRecord.mission_started_at` field.

### CSRF demonstration
- New page `/evil/csrf-demo` inside target-agent. Local-only attacker
  page that POSTs a forged form to `/profile/update`. The Workspace
  briefing instructs the learner to visit it after logging in.

### Workspace UI rebuild
- Removed: bottom CLI drawer, per-task CLI buttons, "Type these commands",
  Options form, Target host/port form.
- New 3-column layout:
  - **Left:** mission sidebar with timer, progress, learner-step checklist
    that tracks evidence-driven completion.
  - **Center:** `LabBrowser` iframe with browser-style chrome (refresh
    button, address bar, open-in-new-tab) embedding the vulnerable page
    at `/target/<module path>`.
  - **Right:** `LearningPanel` with objective, Check Progress button,
    evidence cards (severity-colored), what-to-look-for, defensive insight,
    MissionCompleteSummary at the top once all success criteria are met.
- "Run Demo Simulation" affordance is hidden behind a collapsed
  "Advanced / Developer Tools" tab — opt-in only.
- START button only sets `mission_started_at` and starts the timer. The
  user generates evidence by clicking inside the iframe.

### Module-by-module evidence map

| Module        | Page                  | Tasks                                       | Success criterion                       |
|---------------|-----------------------|---------------------------------------------|-----------------------------------------|
| recon         | `/`                   | visit / explore / find clue                 | portal_visited                          |
| brute_force   | `/auth/login`         | submit / fail x3 / valid login              | brute_force_pattern + credential_found |
| xss           | `/search`             | use / payload / reflection                  | xss_payload_observed + reflected       |
| cmd_injection | `/system/ping`        | ping / separator / output indicator         | command_injection_detected              |
| dir_traversal | `/files/read`         | view / traversal / sensitive file           | sensitive_file_disclosed                |
| file_upload   | `/files/upload`       | upload / save / dangerous extension         | unrestricted_upload_detected            |
| csrf          | `/profile/`+lure page | view / lure visit / forged update           | profile_changed_without_csrf            |

### File upload terminology
- File upload module is described as **Unrestricted dangerous file upload**,
  not RCE. Uploaded files are stored under `/app/static/uploads/` and
  served statically — they are not piped to a runtime, so the proper
  educational claim is "unrestricted upload", not "remote code execution".

### Mission page
- `Mission.jsx` now prefers `briefing.steps` (learner_steps) over the
  technical `module.steps` from the engine.

## How to run

```bash
docker compose up --build -d
# Open http://localhost:3000
```

## Manual QA

For each module:
1. Open from Modules page or Dashboard
2. Click START — confirm timer starts but no attack runs
3. Use the iframe — confirm forms submit inside `/target/...`
4. Click CHECK PROGRESS — confirm task completion + evidence cards appear
5. Continue until all 3 tasks ✓ — confirm MissionCompleteSummary appears

## Verified before shipping

- 29 frontend JS/JSX files lint clean (esbuild)
- 83 Python files parse clean
- docker-compose.yml valid
- Phase 1: 7 integration tests passed (forms, redirects, XSS reflection,
  CSRF lure, upload result link)
- Phase 2: end-to-end live test through all 7 modules — manual learner
  activity → events recorded → progress computed → success=True

## Limitations

- No live `docker compose build` was run (no Docker daemon in dev sandbox).
  The Dockerfiles are unchanged from the working v4 build.
- No `npm install` / `vite build` ran (no network in sandbox). All JSX
  parses cleanly — first `docker compose up --build` will run them.
