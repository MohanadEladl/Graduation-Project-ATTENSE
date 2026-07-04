# ATTENSE v3 — Guided Cyber Range Implementation Plan

Source brief: `New_requirment.txt` at repo root. This document captures the
concrete engineering plan derived from that brief, scoped so each step is
independently shippable.

## North star

Transform the CLI shell into a TryHackMe/HTB-style guided platform:
mission dashboard → mission page → workspace with live attack log,
per-step progress, editable options, and blue-team detection feedback —
without re-writing the existing attack engine.

## Step 1 — Dashboard & Mission page (✅ complete)

- React Router with `AppLayout` shell (nav + health pill).
- `/` Dashboard: mission grid with category pill filter, text search,
  hover-glow cards driven by `GET /api/modules`.
- `/mission/:moduleId`: hero card (icon, scenario, severity, stats grid),
  task accordion for `module.steps` (title + hint + expected outcome),
  START LAB and OPEN SHELL CTAs.
- Legacy `/shell` xterm flow preserved under its own route.

## Step 2 — Session endpoints + action runner (✅ complete)

Backend exposes per-mission sessions that reuse the existing
`AttackSession` so REST, WS, and the xterm shell all hit the same engine
path.

Endpoints:
- `POST /api/sessions {module_id}` → create + banner
- `GET /api/sessions`, `GET /api/sessions/:id`
- `DELETE /api/sessions/:id`
- `POST /api/sessions/:id/options {key,value}`
- `POST /api/sessions/:id/target {host, port?}`
- `POST /api/sessions/:id/start`
- `GET /api/sessions/:id/logs`
- `WS /ws/sessions/:id` — snapshot + live log + accepts `start`,
  `set_option`, `set_target` messages.

## Step 3 — Workspace route (✅ complete)

`/workspace/:sid` three-pane TryHackMe-style workspace:
- Left: mission header + task checklist (✓ marks from
  `snapshot.completed_steps`).
- Center: live `LogView` (timestamps, colour-coded `[+]/[!]/[*]` tags,
  auto-scroll) with START/RERUN + EXIT + status pill.
- Right: editable target, per-option inputs (dirty-aware SET), RESULT
  panel showing verdict or error.
- Mission page START LAB now creates a session and navigates here.
- `useSession(sid)` hook: REST backfill then WS stream with auto-reconnect.

## Step 4 — Detections feed (✅ complete)

Blue-team visibility inside the workspace.

Backend:
- `DetectionBroker` polls `http://signal-store:8000/events` every 1s,
  keeps a 500-event ring, fans new events to WS subscribers.
- `GET /api/detections?since=<ts>&limit=N` (status + events).
- `WS /ws/detections?since=<ts>` — snapshot on connect, `detection`
  pushes thereafter.

Frontend:
- `useDetections({sinceTs})` hook.
- `DetectionsFeed` component: severity pill, rule id, scenario, source
  IP, target, description, timestamps; WAZUH LIVE/WAZUH DOWN pill.
- Workspace center column now splits into attack log (top) + detections
  feed (bottom). Events whose `scenario_id` matches the session get
  "▶ YOU WERE DETECTED" red highlight — that's the actions → detections
  link from the brief.

## Step 5 — Progress & auto-complete (⏳ next)

Today `session_manager.py` only flips every step to complete after the
whole attack finishes. We want honest per-step progress and cross-page
continuity.

Scope:
- **Heuristic per-step completion**: each `module.steps[i]` grows
  optional `markers: [str]`. When a log line contains any marker, mark
  that step complete and emit a `snapshot` push so the workspace ✓
  animates in real time. If `markers` is absent fall back to the
  current "all complete on success" behaviour.
- **Resume an in-progress session**: `GET /api/sessions?module_id=<id>`
  filter; Mission page offers RESUME if a non-`error` session exists.
- **Dashboard progress chip** per card: small `n/total ✓` from the
  latest completed session for that module.
- **Completed-state persistence**: keep completed sessions listed (they
  already persist for the life of the backend process; no disk needed
  for this MVP). Dashboard card reads the latest `completed` snapshot.

## Step 6 — Replay + certificate polish (optional)

- `GET /api/sessions/:id/logs?format=ndjson` download.
- `/workspace/:sid?replay=1` renders the finished logs without opening
  a WS.
- On a fully-completed mission show a small "Mission complete" card
  with duration, steps OK, and a download button.

## Non-goals

- No attack-engine refactor. The engine is invoked exactly how the
  existing xterm shell invokes it.
- No detection archive — signal-store already owns durable events.
- No auth. Lab-only stack.
