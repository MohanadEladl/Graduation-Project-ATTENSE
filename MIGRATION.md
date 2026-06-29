# Repository restructure — current → target layout

Target structure (from the report's Consolidation Strategy), now matched:

```
attense/
├── apps/            control-api, event-api*, signal-mapper, red-team-api, blue-team-api, target-lab
├── frontends/       portal, red-team
├── packages/attense-core/   models, evaluation, repositories, scenarios
├── integrations/    thehive, cortex, wazuh
├── infra/           compose.base.yml, compose.dev.yml, compose.security.yml, compose.ai.yml
├── scripts/         bootstrap, maintenance
└── tests/           unit, integration, e2e
```

\* `event-api` is scaffolded but not split out as a separate service — see
"Not done" below.

**Status: done.** Every directory move, Dockerfile/compose path fixup, and test
relocation has been applied and re-verified (138 Python tests green, `docker
compose config` clean, every service entrypoint import-smoke-tested). What
follows documents what moved, two non-obvious mechanics worth knowing before
touching this tree, and the handful of items still genuinely deferred (they
need a live stack or are a real architecture change, not a file move).

## `packages/attense-core/` — the canonical domain

Extracted from `ATTENSE_app/` into an importable `attense_core` package:

| New canonical home | Came from |
|---|---|
| `attense_core/models/event.py`, `standard_event.py`, `constants.py`, `allowed_events.py`, `event_store.py` | `ATTENSE_app/events/*` |
| `attense_core/models/incident.py` | `ATTENSE_app/incidents/incident.py` |
| `attense_core/models/scenario.py` | `ATTENSE_app/scenario_specs/spec.py` (model half) |
| `attense_core/models/standard_event.schema.json` | `ATTENSE_app/events/standard_event.schema.json` |
| `attense_core/evaluation/metrics.py` | `ATTENSE_app/matrics/metrics.py` |
| `attense_core/evaluation/outcome.py` | `ATTENSE_app/Outcomes/outcome.py` |
| `attense_core/evaluation/reports.py` | `ATTENSE_app/reports/report.py` |
| `attense_core/evaluation/state_machine.py` | `ATTENSE_app/persistence/transitions.py` |
| `attense_core/repositories/events.py` | `ATTENSE_app/persistence/event_repository.py` |
| `attense_core/repositories/incidents.py` | `ATTENSE_app/persistence/incident_projection.py` |
| `attense_core/scenarios/` (loader) + `scenarios/data/*.json` | `ATTENSE_app/scenario_specs/` |

**Compatibility shims**: the `apps/control-api/ATTENSE_app.*` module paths
re-export from `attense_core` (e.g. `ATTENSE_app/events/event.py` is
`from attense_core.models.event import *`). So every consumer (`control-api`'s
controller/routers, `blue-team-api`, `signal-mapper`) keeps working with its
original `from ATTENSE_app.events.event import Event`-style imports unchanged.
Consumers can migrate to importing `attense_core` directly at their own pace;
the shims are deleted once nothing imports `ATTENSE_app.*` anymore.

`packages/attense-core` is on the build/runtime path everywhere `ATTENSE_app`
is imported: copied into both `apps/control-api/Dockerfile` and
`apps/blue-team-api/Dockerfile` images, and added to every test's `sys.path`
bootstrap.

## Service / frontend / integration moves — done

| Target | Came from |
|---|---|
| `apps/control-api/` | `AttensePortal/attense-app/` (auth/company/rooms/scenarios + `controller`, incl. `pipeline/`) |
| `apps/signal-mapper/` | `signal-store/` |
| `apps/red-team-api/` | `red-team/` minus `frontend/` |
| `apps/blue-team-api/` | `blueteam/` (package nested as `blueteam/blueteam/blueteam` — see note below) |
| `apps/target-lab/` | `target-agent/` |
| `frontends/portal/` | `AttensePortal/AttenseFront/attense-react/` |
| `frontends/red-team/` | `frontends/red-team/` |
| `integrations/{thehive,cortex,wazuh}/` | `thehive/`, `cortex/`, `wazuh/` |
| `scripts/bootstrap/` | `setup_thehive.py`, `setup_cortex.py`, `setup_wazuh.py`, `check_secrets.py` |
| `scripts/maintenance/` | `wazuh_agent_watchdog.py`, `close_lab.py` |
| `tests/unit/`, `tests/integration/<service>/` | the per-package `test_*.py` files |

`AttensePortal/` is gone (both children moved out, directory removed empty).

### Two mechanics worth knowing

1. **`apps/blue-team-api/`'s Python package is nested one level deep**, at
   `apps/blue-team-api/blueteam/` — not directly in the service directory.
   `blue-team-api` is hyphenated and not a valid Python identifier, but
   `apps/control-api/controller.py` does `from blueteam.main import app`
   (the embedded-mode import) and the test suite does
   `from blueteam.api.dependencies import ...` — both need a literal,
   importable package named `blueteam` on `sys.path`. Build files (`Dockerfile`,
   `supervisord.conf`, `start.sh`, `test_room_isolation.py`) sit at the service
   root, sibling to the nested package — the same pattern `apps/control-api`
   already uses for `main.py`/`controller.py` vs. its `ATTENSE_app/` subpackage.
   Both Dockerfiles `COPY apps/blue-team-api/blueteam /app/blueteam`
   (collapsing the nesting at the container layer, where "blueteam" is just
   `/app/blueteam` regardless of the host folder name).

2. **Integration test directories under `tests/integration/` are hyphenated**
   (`control-api`, `blue-team-api`, `signal-mapper`, `red-team-api`) to match
   `apps/`. Run them with `unittest discover -s tests/integration/<name>`
   (path-based), never a dotted module name — `tests.integration.control-api...`
   is invalid Python syntax. See `tests/README.md`.

### Real pre-existing bugs fixed incidentally while moving files

- `apps/signal-mapper/Dockerfile` `COPY`'d and `exec`'d `nginx_adapter.py` /
  `signal_mapper_nginx.py` — both deleted in the Phase 8 legacy cleanup. The
  build would have failed; the Dockerfile's nginx-mode branch is removed
  (it was already dead — the mapper only ever ran in Wazuh mode).
- `scripts/bootstrap/check_secrets.py` checked `ROOT / "attense-app" / ".env"`
  — stale since the pre-existing `AttensePortal` split (the real file was two
  levels deeper). Now correctly resolves `apps/control-api/.env`.
- `tests/unit/test_blueteam_packaging.py` pointed at
  `ATTENSE_app/blueteam` — a path that never existed even before this
  restructure. Fixed to the real location.
- `signal-mapper`'s runtime bind-mount of `apps/control-api` (`/attense_app`)
  never got `packages/attense-core` added alongside it like the two Dockerfiles
  that `COPY` it did — caused a real `ModuleNotFoundError: attense_core`
  crash loop, only caught by actually bringing the stack up. Fixed by adding
  `packages/attense-core/attense_core:/app/attense_core:ro` to its volumes in
  `infra/compose.base.yml` (lands under the existing `PYTHONPATH=/app`).
- `/attense/actions` (the analyst-action JSONL store, added during the
  watcher-pipeline integration) had no Dockerfile step creating it, unlike
  `/attense/data`/`/attense/temp` — the non-root `appuser` got a silently
  swallowed `PermissionError` trying to create it at runtime. Fixed in both
  `apps/control-api/Dockerfile` and `apps/blue-team-api/Dockerfile`. See
  `WATCHER_PIPELINE_INTEGRATION.md` for the full live-test writeup.
- `pipeline/report_generator.py` imported `google.genai` unconditionally at
  module level, crashing the whole pipeline if it wasn't installed — and it
  isn't (it requires `pydantic>=2.12.5`, conflicting with this project's
  pinned `2.10.6`). Made the import lazy so a missing package degrades to the
  already-documented plain-text fallback instead of crashing.

All of the above were found by actually building the images and running the
full `docker compose up` stack (not just `docker compose config`), then
driving a real incident through `POST /blueteam/analyst-action` and
`python -m pipeline.run_pipeline` inside the live `attense_app` container —
see `WATCHER_PIPELINE_INTEGRATION.md`.

## `infra/` compose split — done

`docker-compose.yml` at the repo root is now a thin `include:` wrapper over:

- `infra/compose.base.yml` — target-lab, signal-mapper, control-api +
  blueteam-image, attackbox, zap, red-team-api, red-team-frontend, portal.
- `infra/compose.security.yml` — wazuh-manager, cassandra, elasticsearch,
  thehive (+ cassandra-init, thehive-init), cortex (+ cortex-init),
  check-secrets, wazuh-init, wazuh-agent-watchdog.
- `infra/compose.ai.yml` — ollama.
- `infra/compose.dev.yml` — source-mount hot reload for the portal frontend
  (apply on top: `-f docker-compose.yml -f infra/compose.dev.yml`).

All validated with `docker compose config` (root wrapper resolves to the same
21 services as passing all three `-f` files directly). The `x-default-logging`
YAML anchor is redefined in each file (anchors are file-local); named volumes
shared across files (`wazuh_alerts`) are declared identically in both and
merge without conflict.

**Not done:** decoupling `compose.base.yml` from `compose.security.yml`/
`compose.ai.yml` so a lightweight dev-only stack could run from `base` alone.
`attense-app` hard-`depends_on` `check-secrets`+`thehive`; `red-team-backend`
on `ollama`+`check-secrets`. The file split is real (validated separately),
but all three are still always run together — see `tests/README.md` Phase 7.

## Not done — real architecture work, not file moves

- **`apps/event-api` is scaffolded only** (a `NOTE.md`, no code). The report
  splits event-ingest (currently `api/incidents_router.py` +
  `controller.process_event`) into its own service from `control-api`. That
  means a second FastAPI process/container and repointing every producer
  (red-team's `event_sink.py`, the signal-mapper) at its URL — a real service
  split needing a live stack to verify, not a directory rename.
- **Network segmentation** (edge/app/sandbox/telemetry/blue-data) and
  **removing fixed `container_name`s** (the watchdog/init scripts `docker exec`
  by name) — both still pending, per Phase 7.
- **Guided/operator route merge** in `apps/target-lab` behind one
  `ScenarioProfile` policy (report step 6) — not started.
