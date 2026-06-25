# ATTENSE test suite

Phase 1 of `ATTENSE_Refactoring_Optimization_Report.md`: lock down the **current**
behaviour of the incident-evaluation domain layer before later rewrites. These
tests assert what the code does *today* — quirks and known bugs included — so
any behavioural change is caught. Phases 2-9 (event contract, persistence,
correlation, Blue Team isolation, scenario consolidation, infra, legacy
cleanup, CI) each added their own suite as the work progressed; the folder
restructure (matching the report's target `apps/`/`packages/`/`tests/` tree)
centralized all of them here.

## Layout

```
tests/
├── unit/            pure logic, no I/O, no cross-service wiring
├── integration/      cross-module / API-layer / multi-component, one per service
│   ├── control-api/
│   ├── blue-team-api/
│   ├── signal-mapper/
│   └── red-team-api/
└── e2e/              empty for now — see tests/e2e/README.md
```

No `__init__.py` files — each test file inserts the package roots it needs
onto `sys.path` itself (see each file's header), so `unittest discover` works
the same whether invoked by path or imported directly.

## Running

```bash
# everything (from repo root)
py -m unittest discover -s tests/unit -p "test_*.py"
py -m unittest discover -s tests/integration/control-api -p "test_*.py"
py -m unittest discover -s tests/integration/blue-team-api -p "test_*.py"
py -m unittest discover -s tests/integration/signal-mapper -p "test_correlation.py"
py -m unittest discover -s tests/integration/red-team-api -p "test_*.py"
```

Service directory names under `integration/` are hyphenated (`control-api`,
`blue-team-api`, ...) to match `apps/`, so they're addressed by **path**
(`discover -s ...`), never by dotted module name (`tests.integration.control-api...`
is invalid Python syntax — hyphens aren't allowed in import statements).

`test_webhook_local.py` and `test_mapper_suitability.py` under
`integration/control-api` and `integration/signal-mapper` are manual
diagnostic scripts (not `unittest.TestCase`s) kept alongside the automated
tests for the service they exercise; see their own header comments.

## Files (unit)

- `test_characterization_domain.py` — event model validation, the incident
  state machine (every transition), TTD/TTC metrics on fixed UTC timestamps,
  outcome classification, the event store, duplicate / out-of-order events, and
  a full-lifecycle integration test asserted at the report level.
- `test_characterization_scenarios.py` — a snapshot (count, ids, required keys,
  content hash) of `Scenarios/scenarios.json`, so the Phase 6 scenario
  consolidation can be proven to preserve the catalogue.
- `test_standard_event.py` — Phase 2 canonical event contract: `StandardEvent`
  validation (enums, UTC-aware-only `occurred_at`, the legacy `timestamp` alias,
  strict extra-field rejection), the producer adapters, the bridge down to the
  legacy `Event`/state machine, enum sync with `allowed_events`, and that the
  committed JSON schema matches the model. Requires `pydantic`.
- `test_ai_dataset.py`, `test_blueteam_packaging.py` — pre-existing structural
  checks (AI dataset CVSS-vector/schema validation; blueteam package AST-parses
  and uses only relative internal imports). `test_blueteam_packaging.py`'s
  target path was already stale before this restructure (pointed at a
  `blueteam` folder nested inside `ATTENSE_app` that never existed there);
  fixed to the real location while relocating it.
- `Testing.py`, `simulator.py` — legacy/superseded manual scripts, kept for
  historical reference (see "Note on the legacy `Testing.py`" below).

## Phase 2 — the canonical event contract

`apps/control-api/ATTENSE_app/events/standard_event.py` (`StandardEvent`) +
`constants.py` are the single validated event format and the **schema
authority**, now mirrored by the canonical `attense_core.models.standard_event`
in `packages/attense-core` (see "Folder restructure" below) — the JSON schema is
generated from the model, not hand-written:

```bash
python scripts/generate_event_schema.py           # regenerate the schema file
python scripts/generate_event_schema.py --check    # CI: fail if out of date
```

`StandardEvent` is additive: the legacy `Event` and the incident state machine
are untouched, and `StandardEvent.to_legacy_event()` bridges back to them, so the
Phase 1 characterization behaviour is preserved until the Phase 3 storage swap.
The one HTTP ingest endpoint (`POST /api/incidents/events`) now validates against
`StandardEvent` (malformed events get `422`, not a silent `202`).

> The old hand-written `event.schema.json` is **superseded** by the generated
> `standard_event.schema.json` (now canonically at
> `packages/attense-core/attense_core/models/`) and is no longer read by any code.

## Phase 3 — durable persistence + incident projection

The canonical home is now `packages/attense-core/attense_core/repositories/`
(bridged from the old `apps/control-api/ATTENSE_app/persistence/` via
compatibility shims — see "Folder restructure"). Events and incidents are
stored as **logs in JSON**; the interface is storage-agnostic so a real
database swaps in at the end without contract changes.

- `repositories/events.py` (`EventRepository`) — over an append-only
  `events.jsonl` (the durable, ordered, inspectable record) + an `incidents.json`
  projection snapshot. `append()` ignores duplicate `event_id`s (fixes the
  Phase 1 double-counting gap), keeps one time-ordered timeline per incident, and
  the projection is always rebuildable from the log (`rebuild_projection()`), so
  a crash between the event append and the projection write self-heals on reload.
- `repositories/incidents.py` (`IncidentProjection`) — `from_events()` **reuses**
  the legacy `Incident`/metrics/outcome code, so computed state stays identical
  to the Phase 1 behaviour; durability/idempotency come from the storage layer.
- `evaluation/state_machine.py` — explicit forward-transition table; out-of-order
  events are recorded as advisory `anomalies` (e.g. containment before detection).

`tests/integration/control-api/test_persistence.py` covers idempotency, time
ordering, restart survival, legacy parity, transition anomalies, and the
controller dual-write.

The store is wired into `controller.process_event` as an **additive dual-write**,
gated by the `ATTENSE_EVENT_STORE_DIR` env var (unset = disabled = unchanged
behaviour). Switching the read/report endpoints onto the repository and removing
the JSONL tail + in-memory registries (report Phase 3, steps 6-7), and replacing
the JSON backend with a real database, are deferred follow-ups.

## Phase 4 — correlation (one exercise = one incident)

Fixes the two bugs that split an exercise or corrupted TTD:

- **Red-team TTD anchor** (`apps/red-team-api/core/engine.py`) — the
  `malicious_action_executed` event now carries the attack **start** time
  (`AttackResult.started_at`), not the completion time. `event_sink.py` also
  forwards `run_id` / `source_event_id`.
- **Wazuh incident split** (`apps/signal-mapper/app/mapper.py`) — a detection now
  correlates to the shared exercise `incident_id` (`INCIDENT_ID` env) instead of
  minting `wazuh-<alert id>`; the Wazuh alert id is preserved separately as
  `source_event_id`.
- **Contract** — `StandardEvent` gains `source_event_id` (external ids kept
  separate from `incident_id`) and auto-promotes correlation fields that the
  legacy bridge folds into metadata, so producers that only set them in metadata
  still round-trip.

Tests: `tests/integration/control-api/test_correlation.py` (contract + the
durable-store proof that two correlated events form one incident with a correct
non-zero TTD), `tests/integration/signal-mapper/test_correlation.py`, and
`tests/integration/red-team-api/test_correlation.py`.

Generating the exercise/run id at start and threading `run_id` through the
session/control plane is the remaining (control-plane) part of "carry it
through"; the fields and plumbing are in place for it.

## Phase 5 — one Blue Team topology (cross-room isolation)

Lives in `apps/blue-team-api/blueteam/` (the package is nested one level under
the service directory — `blue-team-api` is hyphenated and can't be a Python
import name; see "Folder restructure" below):

```bash
# from repo root
py -m unittest discover -s tests/integration/blue-team-api -p test_room_isolation.py
```

Exit condition — two rooms on one Blue Team instance cannot read/modify each
other's incidents — enforced in the **data layer**:

- `infrastructure/eventstore/event_emitter.py` — each incident is tagged with
  the room that created it; `get_or_create` / `get_incident` raise
  `CrossRoomAccessError` on a cross-room attempt, and `all_incidents(room_id)`
  is a room-scoped query.
- `api/dependencies.py` — `require_room` takes the caller's room from the
  `X-Room-Id` header (not the forgeable body); missing room → 401. The attacher
  is now built lazily (no import-time `Settings()` side effect).
- `api/router.py` services thread `room_id` into every action; `main.py` maps
  `CrossRoomAccessError` → 403.

**Deferred (infra cutover, needs the running stack):** collapsing the three
deployment models into one shared standalone API — removing the embedded
uvicorn from `controller.run()`, the dynamic per-room `spin_up_blueteam`
containers, and the build-only `blueteam-image` compose service, and repointing
`EVENT_STORE_URL` + the attense-app health check (`:8010/health`) at the
standalone service. The data-layer isolation added here is the prerequisite that
makes a single shared instance safe; the compose/health/networking rewiring is a
coordinated change to do against a live stack.

## Phase 6 — consolidate scenarios (one versioned source)

`apps/control-api/ATTENSE_app/scenario_specs/` is the canonical, versioned
scenario definition — one file per scenario (`data/APP-0X.json`), validated by
the `ScenarioSpec` pydantic model and served read-only through `/api/scenarios`
(+ `/{attack_id}`). Tests: `tests/integration/control-api/test_scenarios_spec.py`
(load/validate, loader helpers, the API via `TestClient`, and a
**catalogue-parity** test proving the specs preserve the original
`scenarios.json` so nothing was lost migrating).

> The package is `scenario_specs`, not `scenarios`, because Windows'
> case-insensitive filesystem collides a lowercase `scenarios/` with the legacy
> `ATTENSE_app/Scenarios/` (which still holds `scenarios.json`).

**Deferred (the bulk — consumers + needs the stack to verify):** point the
consumers at `/api/scenarios` and delete their hard-coded copies — the red-team
frontend (`frontends/red-team/src/data/missionBriefings.js`, ~1.4k lines of
briefings/lab-steps/defense breakdowns), the backend `report_agent.py` /
`lab_progress.py` / `lab_analysis.py`, and finally `Scenarios/scenarios.json`.
Also the report's step 6: merge the guided (`apps/target-lab/app/routes/`) and
operator (`routes_op/`) route modules behind one `ScenarioProfile`/mode policy.

## Phase 7 — simplify infrastructure

`docker-compose.yml` at the repo root is now a thin `include:` wrapper over
`infra/compose.base.yml` + `compose.security.yml` + `compose.ai.yml` (report's
"split the Compose stack by concern"); `infra/compose.dev.yml` carries the
source-mount hot-reload override. All four validate with `docker compose config`.

**Done (additive, `docker compose config`-validated):**
- **Log rotation** on every long-running service via a shared
  `x-default-logging` anchor (redefined per-file — YAML anchors are file-local).
- **Memory limits** on the heavy stateful services (wazuh 2g, cassandra 2g,
  elasticsearch 1536m, thehive/cortex 1280m, ollama 4g) — conservative defaults
  (≈3× configured heap); not load-verified.
- **Cassandra version aligned** — `cassandra-init` and the cluster both `3.11`.

**Deferred (structural — needs a live stack to verify, and app-level changes):**
- **Decoupling the base/security/ai `depends_on` edges** so a lightweight
  dev-only stack (no TheHive/Cortex/Ollama) can run from `compose.base.yml`
  alone — currently `attense-app` hard-depends on `check-secrets`+`thehive`,
  and `red-team-backend` on `ollama`+`check-secrets`. The file split is done;
  the dependency decoupling that would let `compose.base.yml` run standalone
  is not.
- **Network segmentation** (edge/app/sandbox/telemetry/blue-data) — wrong
  reachability silently breaks connectivity; unverifiable without running.
- **Removing fixed `container_name`s** — blocked: the watchdog/init scripts
  `docker exec` services by container name; removing the names breaks them
  until those scripts move to service-name lookup.
- **Docker-socket proxy**, **Python image standardization** (3.11 → 3.12), and
  **prod multi-stage frontend builds** outside dev.

## Phase 8 — delete verified-legacy code

Deletion gated on import/dependency analysis: a file was removed only after a
full-repo reference sweep proved it unused.

**Deleted (zero references, confirmed dead):**
- `report_generator.py` (now under `apps/red-team-api/backend/`) — the active
  report path is `report_agent` (`main.py` imports/uses it).
- `nginx_adapter.py` + `signal_mapper_nginx.py` (signal-mapper) — the inactive
  Nginx-mode mapper; `app/main.py` uses the Wazuh `app.mapper`. The Dockerfile's
  matching dead `COPY`/`CMD` branch was fixed during the folder restructure.
- `test_query.py`, `test_resolution.py` — ad-hoc root debug probes, unreferenced.

**Kept — the report's "unused" claim is stale; these are still wired:**
- `apps/control-api/core/port_pool.py` — **active**: imported and
  `release()`-called by `room_manager.py`, and it is the room reservation ledger
  that `SESSION_CONTEXT.md` records as recently fixed.
- `apps/red-team-api/backend/shell/router.py` + `/ws/shell` — **the frontend
  depends on it** (`useShell.js`, `Shell.jsx`, the `/shell` route in `App.jsx`).

**Ready but not executed (build change, can't verify offline):** remove
Supervisor from the Blue Team image (`apps/blue-team-api/supervisord.conf` runs
exactly one process) — needs an image build to verify, entangled with the
deferred Phase 5 blueteam topology cutover.

## Phase 9 — CI + acceptance gates

`.github/workflows/ci.yml` runs the acceptance checklist as gates, mostly by
*running these suites* on the new `tests/` paths. All offline-verifiable gates
run locally and pass: 138 Python tests (94 unit + 44 integration), `docker
compose config`, secret hygiene.

**Not wired (need image builds / a live stack):** container vulnerability scan
and the boot-the-stack end-to-end smoke test — see `tests/e2e/README.md`.

## Folder restructure (`apps/`, `packages/attense-core/`, `frontends/`, ...)

Matches the report's Consolidation Strategy target tree. Two notable mechanics,
both load-bearing for anything that imports across service boundaries:

1. **`packages/attense-core/`** holds the canonical domain (models/evaluation/
   repositories/scenarios). The old `apps/control-api/ATTENSE_app/*` modules are
   now **compatibility shims** (`from attense_core.models.event import *`), so
   every existing consumer keeps working unchanged while new code can import
   `attense_core` directly. See `MIGRATION.md`.
2. **`apps/blue-team-api/`'s Python package is nested one level deep**, at
   `apps/blue-team-api/blueteam/` (not directly in the service directory).
   `blue-team-api` is hyphenated and not a valid Python identifier, but both
   `apps/control-api/controller.py` (`from blueteam.main import app`, embedded
   mode) and the test suite need a literal importable package named `blueteam`.
   Build files (Dockerfile, `supervisord.conf`, `start.sh`, the test) sit at the
   service root, sibling to the nested package — the same pattern
   `apps/control-api` uses for `main.py`/`controller.py` vs. its `ATTENSE_app/`
   subpackage.

Every Dockerfile `COPY` path, `docker-compose.yml`/`infra/compose.*.yml` build
context and volume mount, and test `sys.path` bootstrap was updated for the new
locations and re-verified (138 tests green, `docker compose config` clean).

## Known bugs/quirks deliberately pinned (not regressions)

These are asserted as the *current* behaviour. When a later phase intentionally
fixes one, the corresponding test is expected to fail and must be updated in the
same commit as the fix.

- **`is_false_positive` is unreachable.** `alert_raised` back-fills `start_time`,
  but `is_false_positive` requires `start_time is None`, so a lone `alert_raised`
  reports `INCOMPLETE`, never `FALSE_POSITIVE`. `alert_denied` sets status
  `FALSE_POSITIVE` but `classify_outcome` has no case for it, so its outcome is
  also `INCOMPLETE`.
- **No event-ID idempotency** in the legacy in-memory path. Replaying an event
  with the same `event_id` is applied twice (e.g. `containment_failures`
  double-counts). The durable repository (Phase 3) fixes this for its own path.
- **Out-of-order events corrupt metrics.** Containment before detection yields a
  negative TTC; an `alert_raised` before `malicious_action_executed` yields
  `TTD == 0` and leaves status stuck at `NOT_STARTED`. This is the correlation
  bug Phase 4 targets.
- **Naive timestamps are accepted** by the legacy `Event`. `StandardEvent`
  (Phase 2) rejects them; the pinning test documents the legacy gap.

## Note on the legacy `Testing.py`

`tests/unit/Testing.py` predates the `alert_raised` start-time fallback and its
`test_false_positive_case` **fails** against the current code (a lone
`alert_raised` now classifies as `INCOMPLETE`). It is left untouched/unrun by
CI for historical reference — the characterization suite (`test_characterization_domain.py`)
supersedes it.
