# ATTENSE v3 — Progress Tracker

Tracks delivery against `docs/IMPLEMENTATION_PLAN.md`. Update after each
completed step.

## Status

| # | Step                              | Status      | Commit |
|---|-----------------------------------|-------------|--------|
| 1 | Dashboard & Mission page          | ✅ complete | 88015a9 |
| 2 | Session endpoints + action runner | ✅ complete | 88015a9 |
| 3 | Workspace route                   | ✅ complete | 88015a9 |
| 4 | Detections feed                   | ✅ complete | 88015a9 |
| 5 | Progress & auto-complete          | ✅ complete | cc1cc18 |
| 6 | Replay + certificate polish       | ✅ complete | 46a8916 |
| 7 | UX polish (v6.2)                  | ✅ complete | —      |
| 8 | Post-Mission Report System (v6.2) | ✅ complete | —      |

## Step 5 shipped

- **Per-step auto-complete**: `SessionRecord.append_log` runs every line
  through `_match_step_markers`; the first match flips that step
  complete. A progress sentinel rides the same subscriber queue and is
  translated into a `snapshot` WS message so the workspace ✓ ticks live
  during the attack (observed 0→1→2 for `brute_force`).
- **Markers schema**: step dicts grow an optional `markers: [str]` list
  (case-insensitive substring). Populated for `brute_force` and `xss`;
  other modules fall back to the "all steps complete on success"
  behaviour.
- **List filter**: `GET /api/sessions?module_id=<id>` returns only the
  sessions for a given module.
- **Dashboard progress chips**: cards load sessions with the modules and
  render an `n/total` or `LIVE` chip per mission using the best-ranked
  session (running > completed > idle, tiebreaker created_at).
- **Resume Mission UX**: Mission page queries sessions for its module;
  if any non-errored session exists the CTA becomes
  `RESUME MISSION →` with a secondary `NEW SESSION` affordance and a
  progress hint.
- Smoke test: `scripts/progress_ws_smoke.py` drives the whole chain.

## Step 6 shipped

- **NDJSON export**: `GET /api/sessions/{sid}/logs?format=ndjson`
  returns the full log buffer newline-delimited with
  `Content-Disposition: attachment; filename="attense-<module>-<sid>.ndjson"`.
  JSON form is unchanged (default/missing `format` still returns the
  object body).
- **Replay route**: `useSession(sid, { replay: true })` skips the
  WebSocket and only does the REST backfill of snapshot + logs.
  `/workspace/:sid?replay=1` opts in via `useSearchParams`.
- **Replay UX in Workspace**: LIVE pill swaps to REPLAY, START is
  hidden, options/target inputs are locked (`mutationsDisabled`),
  EXIT becomes CLOSE (no DELETE), header shows a one-click
  DOWNLOAD NDJSON link.
- **Mission Complete overlay**: when `snapshot.state === 'completed'`
  a card floats over the log pane with DURATION (from
  `result.duration_ms`), STEPS (`completed_steps/total_steps`),
  summary/error body, a DOWNLOAD NDJSON button, and an
  OPEN AS REPLAY shortcut (hidden in replay).

## Backend endpoints (live)

- `GET  /health`
- `GET  /api/modules`, `GET /api/target`
- `POST /api/sessions`, `GET /api/sessions`, `GET /api/sessions/{sid}`,
  `DELETE /api/sessions/{sid}`
- `POST /api/sessions/{sid}/options`, `POST /api/sessions/{sid}/target`,
  `POST /api/sessions/{sid}/start`
- `POST /api/sessions/{sid}/execute`
- `POST /api/sessions/{sid}/check-progress?mode=tutorial|lab`
- `POST /api/sessions/{sid}/reset-evidence`
- `POST /api/sessions/{sid}/restart`
- `GET  /api/sessions/{sid}/logs`
- `GET  /api/sessions/{sid}/lab-analysis`
- `GET  /api/sessions/{sid}/report`
- `POST /api/sessions/{sid}/report/regenerate`
- `WS   /ws/sessions/{sid}` (snapshot + log + control messages)
- `GET  /api/detections?since=<ts>&limit=N`
- `WS   /ws/detections?since=<ts>`
- `GET  /api/operator/attackbox/status`
- `POST /api/operator/attackbox/exec`
- `GET  /api/operator/attackbox/evidence?since=<ts>`
- `GET  /api/operator/zap/status`
- `GET  /api/operator/zap/history?limit=N`
- `POST /api/operator/zap/repeater/send`
- `WS   /ws/shell` (legacy)

## Frontend routes (live)

- `/` Dashboard
- `/missions` Mission list
- `/modules` Module library
- `/mission/:moduleId` Mission details + START LAB
- `/workspace/:sid` Three-pane workspace (lab browser + sidebar + learning panel)
- `/report/:sid` Post-mission report (grade, ideal approach, vulnerability breakdown)
- `/shell` Legacy xterm
- `/detections` Detections feed
- `/reports` Reports list
- `/settings` Settings

## Smoke tests (in `scripts/`)

- `ws_smoke.py` — legacy shell WS banner + prompt
- `session_ws_smoke.py` — session create → WS start → state=completed
- `detections_ws_smoke.py` — snapshot on connect, push on injected alert

## Step 7 shipped — UX polish (v6.2)

- Sidebar open/close uses framer-motion width animation (`Sidebar.jsx`,
  `AppLayout.jsx`).
- Dashboard module cards navigate to `/mission/:id` (was broken).
- Target-agent login page rebranded from "ATTENSE PORTAL" to "Lab"
  (`auth.py` `_LOGIN_PAGE`).
- Removed "Target not available" overlay and iframe pointer-events lock in
  lab mode (`Workspace.jsx`).
- Terminal panel (AttackBox / ZAP) has minimize/maximize chevron toggle;
  panel height animates between 42 px and 320 px.
- MissionSidebar (left) and LearningPanel (right) have collapse/expand
  toggles; framer-motion animates width to 36 px when collapsed.
- "Reveal Hints" section hidden in Tutorial mode — only visible in Lab mode.

## Step 8 shipped — Post-Mission Report System (v6.2)

- `red-team/backend/report_generator.py` (new): grade + score engine,
  per-module ideal approach / vuln explanation / defensive controls for
  all 7 modules.
- `SessionRecord.report_cache` field for in-memory caching.
- `GET /api/sessions/{sid}/report` and `POST .../report/regenerate`
  endpoints in `main.py`.
- `red-team/frontend/src/routes/MissionReport.jsx` (new): 9-section
  animated report page at `/report/:sid` with grade badge, copyable
  commands, and print/PDF export.
- `App.jsx` wired `/report/:sid` route.
- `client.js` added `getReport` and `regenReport` helpers.
- `Workspace.jsx`: pre-warms report cache on mission success; slide-up
  completion banner with "VIEW REPORT →" link.
- `Dashboard.jsx`: REPORT action navigates to `/report/:sid`.

## Known state at last update

- All containers rebuilt and healthy after v6.2 changes
  (`docker compose build --no-cache && docker compose up -d`).
- 29 frontend JS/JSX files lint clean (esbuild).
- 83+ Python files parse clean.
- Report generator functional test passed (graded mock session, all
  required keys present, grade=F for zero-evidence session).
- Workspace completion banner verified end-to-end.
