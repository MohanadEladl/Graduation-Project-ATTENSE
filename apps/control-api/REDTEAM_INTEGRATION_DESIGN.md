# Red Team Integration — Design (Phase 0, no code yet)

> Status: **design only**. Three open questions (bottom) must be answered before
> Phase 1 code begins.

## Current state

- `red_team_members[]` exists in the room JSON schema but is never populated.
- attense-app's API is entirely blue-team-facing (`auth`, `company`, `rooms`,
  `incidents`).
- A **separate `red-team/` FastAPI service already exists** with its own attack
  orchestration: `session_manager`, `chain_engine`, `action_trace`,
  `report_agent`. Critically, it has **its own session model**, distinct from
  attense-app's `core/session_store.py` (this is the "two session ids"
  distinction: attense-app session = *who is logged in*; red-team session =
  *one attack exercise instance*).

## What red team needs

1. **Auth into a room** — a red-team user authenticates and joins a room,
   populating `red_team_members[]`.
2. **Action logging against the room/incident model** — attacker actions are
   recorded and linked to the room's `incident_id`, so the blue-team
   incident/report model reflects attacker activity.

## The fork

| Concern | A. Build native in attense-app | B. Integrate existing `red-team/` *(recommended)* |
|---|---|---|
| Attack execution | Reimplement orchestration | Reuse `chain_engine` / `session_manager` (already real) |
| Action log | New per-room log in attense-app | Bind red-team `action_trace` to room + incident |
| Auth | Single model | Reconcile attense-app `session_store` ↔ red-team `session_manager` |
| Risk | Duplicates a working engine | Cross-service auth + data sync |

## Recommended approach: B + a thin native membership layer

- **Phase 1 (small, self-contained)** — native room membership:
  `POST /api/rooms/{id}/redteam/join` + `leave`, authenticated, populating
  `red_team_members[]`. No cross-service dependency.
- **Phase 2** — auth handoff: binding an attense-app session to a red-team
  session on join. Likely attense-app issues a scoped token the red-team
  service trusts, resolving the dual-session model.
- **Phase 3** — action logging: pass `room_id` + `incident_id` into red-team
  session creation, tag `action_trace`, and surface it in
  `GET /api/rooms/{id}` alongside the `incidents_detail` added in the
  room↔incident wiring work.

## Open questions (blockers for Phase 1)

1. Which roles count as "red team"? `professional` / `intermediate` (the
   existing non-Hive roles)? Or a new dedicated role?
2. Should attacker actions live in attense-app's data, or stay in the red-team
   service's `action_trace` and be surfaced on read?
3. One auth across both services (SSO/scoped-token handoff), or separate logins?
