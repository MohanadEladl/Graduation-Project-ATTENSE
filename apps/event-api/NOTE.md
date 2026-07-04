# event-api — not yet split out

The report's target architecture separates `control-api` (auth, companies,
rooms, exercise lifecycle) from `event-api` (event ingest, storage, incident
projection) as two independent services.

Today, event-api's responsibilities still live **inside `apps/control-api`**:

- `api/incidents_router.py` — the `POST /api/incidents/events` ingest endpoint
- `controller.py` — `process_event()` / the durable dual-write
  (`ATTENSE_app/persistence` → `packages/attense-core/attense_core/repositories`)

Splitting these into a standalone `event-api` service means running a second
FastAPI process/container with its own lifecycle, and repointing every producer
(red-team's `core/event_sink.py`, the signal-mapper) at its URL instead of
`attense-app:8020`. That is a real architecture change requiring a live stack to
verify (new compose service, new health check, new `depends_on` edges) — see
`MIGRATION.md` and the Phase 5 blueteam-topology notes for the same class of
deferred work.
