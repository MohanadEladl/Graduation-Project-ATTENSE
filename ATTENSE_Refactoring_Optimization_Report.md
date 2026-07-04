# ATTENSE Refactoring and Optimization Report

## Review Scope

This review covers the source code, Docker configuration, service boundaries, event flow, data persistence, frontend structure, and operational scripts contained in `restructured-sandbox.zip`.

The strongest architectural concern is not code duplication by itself. It is **state duplication**: attack, detection, investigation, containment, and reporting are not guaranteed to use the same incident record. That can produce technically valid-looking reports with incorrect TTD/TTC values.

> **Validation note:** The code and configuration were inspected statically and Python modules were syntax-compiled successfully. The entire Docker stack was not launched end-to-end because it depends on multiple heavyweight external services and runtime credentials.

---

# Redundancy Found

## 1. Two independent incident registries

**Files involved**

- `AttensePortal/attense-app/controller.py`
- `AttensePortal/attense-app/api/incidents_router.py`
- `AttensePortal/attense-app/api/rooms_router.py`
- `blueteam/infrastructure/eventstore/event_emitter.py`
- `blueteam/api/router.py`
- `signal-store/app/mapper.py`

**Overlap**

`controller.py` owns one in-memory incident dictionary and builds reports from it. The Blue Team package owns another in-memory `_incidents`/`_stores` registry. Investigation and containment actions are recorded in the Blue Team registry, while report endpoints read the controller registry.

The signal store is configured to deliver Wazuh detections through two paths:

1. Write an event to the JSONL file consumed by the controller.
2. POST an alert to the Blue Team API, which creates another event in its own registry.

This duplicates the same detection semantically while separating later Blue Team actions from the report-generating state.

**Impact**

- TTD and TTC can be calculated from incomplete timelines.
- An incident can appear detected in one service and still active in another.
- Restarts erase different portions of state independently.
- Duplicate alert events may receive different IDs and timestamps.

**Recommendation**

Replace both registries and the JSONL handoff with one event repository and one incident projection. For the graduation-project scope, SQLite is sufficient; PostgreSQL can be used later without changing the domain model.

---

## 2. Two competing Blue Team deployment models

**Files involved**

- `AttensePortal/attense-app/controller.py`
- `AttensePortal/attense-app/core/room_manager.py`
- `blueteam/Dockerfile`
- `blueteam/supervisord.conf`
- `docker-compose.yml`

**Overlap**

The main application starts the Blue Team API internally in a background thread. At the same time, the room manager can create a separate Blue Team container for each room, and the Compose file contains a Blue Team image service.

The project therefore supports three partially overlapping concepts:

- Embedded Blue Team API inside `attense-app`.
- Standalone Blue Team API image.
- Dynamically-created Blue Team container per room.

**Impact**

- It is unclear which process owns Blue Team state.
- Ports and lifecycle behavior differ between local and room-based execution.
- The same package is deployed through incompatible patterns.
- Per-room containers suggest isolation, but they still share the same target, Wazuh, TheHive, network, and other infrastructure.

**Recommendation**

For the current project, use **one stateless Blue Team API**. Every request and event must include `company_id`, `room_id`, `incident_id`, and `run_id`. Enforce tenant boundaries in the data layer. Only move to a full stack per room later if hard infrastructure isolation is an explicit requirement.

---

## 3. Scenario definitions are duplicated across frontend and backend

**Files involved**

- `red-team/frontend/src/data/missionBriefings.js`
- `red-team/backend/report_generator.py`
- `red-team/backend/report_agent.py`
- `red-team/backend/lab_progress.py`
- `red-team/backend/lab_analysis.py`
- `AttensePortal/attense-app/ATTENSE_app/Scenarios/scenarios.json`

**Overlap**

Attack descriptions, ideal steps, progress rules, vulnerability metadata, scoring hints, and analysis rules are maintained in multiple formats. Some backend code explicitly mirrors frontend content.

**Impact**

- Scenario changes must be repeated manually.
- The frontend can show a step that the backend does not score.
- Reports can use different names or impact descriptions from the exercise screen.
- Adding a seventh scenario becomes unnecessarily expensive.

**Recommendation**

Create one versioned scenario specification per scenario, for example:

```text
packages/attense_core/scenarios/APP-01.yaml
```

Each file should contain metadata, permitted attack chain, target switches, evidence rules, Blue Team evaluation checkpoints, report guidance, and UI briefing text. The backend validates and serves this data through `/api/scenarios`; frontends should not hard-code it.

---

## 4. Guided and operator target routes duplicate business logic

**Files involved**

- `target-agent/app/routes/*.py`
- `target-agent/app/routes_op/*.py`

**Overlap**

The project has parallel route modules for guided and operator modes. Although some operator routes reuse templates, the behavioral logic is still split and repeated.

**Impact**

- Fixes applied to one mode may not reach the other.
- Vulnerability behavior can drift between modes.
- Tests must cover two implementations instead of one implementation with two policies.

**Recommendation**

Use one route implementation per vulnerability and inject a `ScenarioProfile` or `ExerciseMode` policy. The policy should control hints, allowed payload classes, logging detail, reset behavior, and scoring—not duplicate the HTTP handler.

---

## 5. Legacy and apparently unused modules

**Likely candidates**

- `red-team/backend/report_generator.py`
- `signal-store/nginx_adapter.py`
- `signal-store/signal_mapper_nginx.py`
- `AttensePortal/attense-app/core/port_pool.py`
- Legacy shell paths in `red-team/main.py` and `red-team/backend/shell/router.py`
- Root-level ad hoc scripts such as `test_query.py`, `test_resolution.py`, and `test_webhook_local.py`

**Why they appear redundant**

- The active report endpoint uses `report_agent`, not `report_generator`.
- The Compose deployment uses Wazuh mode, leaving the alternate Nginx mapper path inactive.
- The port pool is released by migration-era room logic but is not acquired by the current flow.
- The Red Team contains both the newer session API/WebSocket flow and an older shell path.
- Root scripts overlap with what should be integration tests.

**Recommendation**

Do not delete them immediately. Mark them deprecated, add coverage around the active behavior, verify imports and runtime calls, then remove them in a dedicated cleanup commit.

---

## 6. TheHive provisioning is split between bootstrap and runtime code

**Files involved**

- `scripts/setup_thehive.py`
- `AttensePortal/attense-app/core/hive_provisioner.py`
- Cortex/TheHive initialization services in `docker-compose.yml`

**Overlap**

Both bootstrap scripts and runtime application code create organizations, users, and API credentials. The initialization containers also patch configuration and restart services.

**Impact**

- Provisioning is difficult to make idempotent.
- Runtime state can depend on host-file mutation.
- Credentials can be regenerated or overwritten unexpectedly.
- Troubleshooting requires understanding multiple provisioning owners.

**Recommendation**

Separate responsibilities:

- `bootstrap-security-stack`: creates only the base admin/integration configuration.
- `TenantProvisioner`: the sole runtime component that creates company organizations and users.

Both must be idempotent and store generated identifiers in the application database, not in repeatedly patched source files.

---

## 7. Generated and sensitive files are included in the archive

**Examples**

- `.env`
- `AttensePortal/attense-app/.env`
- `secrets/ATTENSE.env`
- `secrets/enrichment.env`
- `secrets/backups/...`
- `__pycache__/` and `.pyc` files

**Impact**

- Credentials can leak through submitted archives even when `.gitignore` is correct.
- Backup secret files preserve revoked values indefinitely.
- Generated bytecode creates noise and platform-specific artifacts.

**Recommendation**

Rotate every credential present in the archive, remove secret backups, provide `.env.example` files with non-sensitive placeholders, and add an archive/build step that fails when secrets, `.env` files, `.pyc`, or cache directories are included.

---

# Configuration Optimization

## 1. Replace the JSONL event bus with a durable event repository

The current JSONL file is functioning as a transport, persistence layer, and replay log. It has no transaction boundary, no unique constraint, and no reliable multi-process locking.

Use a table similar to:

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor_id TEXT,
    target_id TEXT,
    outcome TEXT,
    metadata_json TEXT NOT NULL
);

CREATE INDEX idx_events_incident_time
ON events (incident_id, occurred_at);
```

Maintain a separate `incidents` projection table for current state and metrics. Insert the event and update the projection in one transaction.

---

## 2. Correct incident correlation and attack timestamps

**Files involved**

- `red-team/core/engine.py`
- `signal-store/app/mapper.py`

The Red Team emits an event for the room incident, but the mapper may derive a new incident ID from the Wazuh alert ID. This can split one exercise into two incidents.

The malicious action event also uses the action's completion time where the attack start/trigger time is needed for TTD.

**Required change**

- Generate the incident ID when an exercise starts.
- Propagate `incident_id`, `room_id`, and `run_id` through the target request and telemetry.
- Configure the mapper to preserve that correlation value.
- Use a timezone-aware `started_at` or exact exploit-trigger timestamp for `malicious_action_executed`.
- Use the Wazuh alert ID as `source_event_id`, not as the ATTENSE incident ID.

---

## 3. Make the Pydantic event model the only schema authority

**Files involved**

- Python event model files
- `event.schema.json`

The JSON Schema and Python validation currently allow different outcomes and require different fields.

**Required change**

- Define one `StandardEvent` Pydantic model.
- Use enums for event type, actor type, outcome, and incident state.
- Generate the JSON Schema from the model during CI.
- Reject naive timestamps; store UTC with an offset.
- Add `schema_version` and `source` fields.
- Add unique-event idempotency in storage.

---

## 4. Split the Compose stack by concern and deployment profile

The root `docker-compose.yml` is large and combines application services, vulnerable labs, Wazuh, TheHive, Cortex, Cassandra, Elasticsearch, Ollama, bootstrap jobs, and watchdogs.

Recommended split:

```text
infra/
  compose.base.yml
  compose.dev.yml
  compose.security.yml
  compose.ai.yml
```

- `base`: control API, event API, frontends, target, red/blue APIs.
- `dev`: source mounts, hot reload, debug ports.
- `security`: Wazuh, TheHive, Cortex, Elasticsearch, Cassandra.
- `ai`: Ollama and model-specific services.

Use Compose profiles so developers can run a lightweight application path without starting the entire security stack.

---

## 5. Segment Docker networks

The current flat network allows the attack environment to reach management databases and security infrastructure directly.

Recommended networks:

```text
edge       -> gateway and frontends
app        -> application APIs
sandbox    -> red backend, attack box, vulnerable target
telemetry  -> target, Wazuh, mapper, event API
blue-data  -> TheHive, Cortex, Elasticsearch, Cassandra (internal)
```

Only multi-homed gateway/integration services should connect across boundaries. Mark data networks `internal: true` where possible.

---

## 6. Remove direct Docker socket access

Several services mount `/var/run/docker.sock`. A read-only filesystem mount does not make Docker API operations read-only.

**Preferred order**

1. Remove runtime container creation for the shared Blue Team model.
2. If orchestration remains necessary, create one minimal orchestration service.
3. Put a Docker socket proxy in front of the daemon and allow only required endpoints.
4. Never expose the socket to Red Team, target, frontend, or general API containers.

---

## 7. Improve container builds and dependency reproducibility

### Frontends

- The Red Team frontend has a lock file but copies only `package.json`; copy `package*.json` and use `npm ci`.
- Generate and commit a lock file for the portal frontend, then use `npm ci`.
- Use the existing portal production multi-stage build in production Compose rather than the development Dockerfile with bind mounts.
- Add long-lived cache headers for hashed assets and compress large video/model assets.

### Python services

- Standardize on one Python version; 3.12 is a practical choice for the current codebase.
- Align `pyrightconfig.json` with the actual runtime version.
- Rename `blueteam/requirments.txt` to `requirements.txt`.
- Replace broad unbounded `>=` dependencies with a generated lock/constraints file.
- Move `pytest`, test helpers, and duplicate packages out of runtime requirements.
- Use non-root users consistently and `COPY --chown` rather than world-writable directories.

---

## 8. Tune stateful security services conservatively

- Align Cassandra image versions used by the main service and initialization job.
- Remove extreme Elasticsearch queue-size overrides unless justified by load tests; they can turn backpressure into memory exhaustion.
- Add explicit health checks and make dependents wait for readiness, not only container start.
- Add resource limits/reservations for Elasticsearch, Cassandra, TheHive, Cortex, Wazuh, and Ollama.
- Add Docker log rotation for every long-running service.

---

## 9. Fix volume ownership and persistence boundaries

- Replace `chmod 777` patterns with fixed UID/GID ownership.
- Avoid persisting complete application directories when only data subdirectories require persistence.
- Review the Wazuh agent volume so an old volume cannot silently mask updated image configuration.
- Add exercise reset/TTL behavior for uploaded files, generated payloads, logs, and target state.
- Persist application state in the database rather than JSON files that are rewritten in full.

---

## 10. Harden secret and internal-service configuration

- Remove hard-coded fallback secrets such as development webhook or containment tokens.
- Fail startup when required production secrets are absent.
- Pass secrets through narrowly scoped files or a secret manager rather than mounting the repository or entire secrets directory.
- Parameterize exact CORS origins and do not use permissive wildcard origins with credentials.
- Authenticate mapper-to-event-store and mapper-to-Blue-Team calls.
- Use service identities with least privilege for TheHive and Cortex.

---

## 11. Reduce frontend and API bottlenecks

**Frontend**

- Split large components such as `Workspace.jsx` and `Gauntlet.jsx` into page orchestration, hooks, state stores, and focused panels.
- Remove unused copied Webflow/p5 assets and lazy-load heavy 3D or visualization libraries.
- Remove duplicate navigation entries.

**Backend**

- Do not regenerate a full report after every incoming event only for logging.
- Maintain metrics incrementally in the incident projection and generate the formatted report on demand.
- Reuse HTTP clients with connection pooling and explicit timeouts.
- Replace full JSON-file scans for room/incident lookup with indexed database queries.
- Do not silently swallow storage or orchestration exceptions; return structured errors and emit operational logs.

---

# Simplification Opportunities

## 1. Use one event-driven incident flow

The simplified flow should be:

```text
Red action / Wazuh alert / Blue action
                 |
                 v
          Event Ingest API
                 |
        validate + deduplicate
                 |
      EventRepository transaction
                 |
        IncidentProjection update
                 |
      TheHive/report/UI subscribers
```

No component should maintain its own authoritative incident timeline.

---

## 2. Use a transition table instead of scattered conditional logic

Represent the state machine explicitly:

| Current state | Event | Next state |
|---|---|---|
| `NOT_STARTED` | `malicious_action_executed` | `ACTIVE_UNDETECTED` |
| `ACTIVE_UNDETECTED` | `alert_raised` | `DETECTED` |
| `DETECTED` | `investigation_started` | `DETECTED` |
| `DETECTED` | `containment_applied` | `CONTAINED` |
| `CONTAINED` | `exercise_ended` | `ENDED` |

Invalid transitions should be logged and rejected or stored with a clear reason. This makes the evaluation engine testable and prevents accidental state jumps.

---

## 3. Treat room isolation as a data model first

For this proof of concept, one service instance per room is unnecessary complexity. Use shared stateless services and require tenant keys on every record. Enforce:

- Unique membership constraints.
- Company/room authorization checks.
- Room-scoped TheHive organization or case mapping.
- Room-scoped event queries.
- Separate run IDs when the same room repeats a scenario.

Full container-level isolation should be a later deployment mode, not a partial Blue-Team-only implementation.

---

## 4. Replace multiple file stores with SQLite

The project currently mixes in-memory dictionaries, JSON files, JSONL, and external service state. SQLite gives the project a simpler and more defendable persistence model without requiring another large service.

Suggested tables:

- `companies`
- `users`
- `memberships`
- `rooms`
- `room_members`
- `exercise_runs`
- `incidents`
- `events`
- `reports`
- `integration_mappings`

This removes full-file rewrites, directory scans, and restart data loss.

---

## 5. Convert scenario code into data plus reusable evaluators

Instead of a separate large Python dictionary for every scenario, define reusable evidence rules such as:

- `wazuh_rule_seen`
- `http_status_seen`
- `process_spawned`
- `file_created`
- `blue_action_completed`
- `within_seconds`

Scenario files combine these rules declaratively. The engine remains small while scenarios grow independently.

---

## 6. Remove Supervisor from the Blue Team image

The Blue Team container currently needs only one API process. Run Uvicorn directly as PID 1. Supervisor adds another configuration layer without supervising multiple meaningful processes.

---

## 7. Separate control-plane operations from exercise execution

The portal/control API should manage users, companies, rooms, and run lifecycle. The sandbox path should execute attacks and emit telemetry. It should not receive broad infrastructure credentials or direct Docker control unless absolutely required.

---

# Consolidation Strategy

## Proposed streamlined repository structure

```text
attense/
├── apps/
│   ├── control-api/                 # auth, companies, rooms, exercise lifecycle
│   ├── event-api/                   # event ingest, storage, incident projection
│   ├── signal-mapper/               # Wazuh/raw signal adapters only
│   ├── red-team-api/                # controlled attack execution
│   ├── blue-team-api/               # investigation and containment actions
│   └── target-lab/                  # vulnerable application and scenario switches
│
├── frontends/
│   ├── portal/
│   └── red-team/
│
├── packages/
│   └── attense-core/
│       ├── models/
│       │   ├── event.py
│       │   ├── incident.py
│       │   └── scenario.py
│       ├── evaluation/
│       │   ├── state_machine.py
│       │   ├── metrics.py
│       │   └── reports.py
│       ├── scenarios/
│       │   ├── APP-01.yaml
│       │   ├── APP-02.yaml
│       │   └── ...
│       └── repositories/
│           ├── events.py
│           └── incidents.py
│
├── integrations/
│   ├── thehive/
│   ├── cortex/
│   └── wazuh/
│
├── infra/
│   ├── compose.base.yml
│   ├── compose.dev.yml
│   ├── compose.security.yml
│   ├── compose.ai.yml
│   ├── nginx/
│   ├── thehive/
│   ├── cortex/
│   └── wazuh/
│
├── scripts/
│   ├── bootstrap/
│   └── maintenance/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── .env.example
├── pyproject.toml
├── Makefile
└── README.md
```

## Consolidation decisions

1. **Canonical event model:** `packages/attense-core/models/event.py`.
2. **Canonical scenario source:** YAML/JSON files under `packages/attense-core/scenarios`.
3. **Canonical incident state:** database-backed `IncidentProjection` in the event API.
4. **Canonical Blue Team deployment:** one shared stateless API for the current version.
5. **Canonical report engine:** one implementation under `evaluation/reports.py`.
6. **Canonical TheHive tenant provisioning:** one runtime provisioner plus one base bootstrap job.
7. **Canonical test entry point:** Pytest-based unit/integration/e2e suites, with ad hoc scripts either converted or removed.

## Components to merge

| Existing components | New component |
|---|---|
| Controller incident dictionary + Blue Team EventEmitter registries + JSONL tail | `EventRepository` + `IncidentProjection` |
| Frontend mission briefing + backend ideal steps/progress/analysis metadata | Versioned scenario specification |
| Guided routes + operator routes | Shared routes + `ScenarioProfile` |
| Multiple report implementations | Single report service |
| Bootstrap/runtime TheHive organization creation | One tenant provisioner with idempotent bootstrap |
| Room JSON lookup + port-pool remnants | Indexed room/run repository |

---

# Actionable Next Steps

## Phase 0 — Protect the current project

1. Create a refactoring branch and tag the current working version.
2. Export only required databases and non-secret configuration.
3. Rotate every credential included in the archive.
4. Remove `.env`, secret backups, cache directories, and generated files from distributable archives.
5. Add automated secret scanning to local hooks and CI.

**Exit condition:** No active credential exists in the repository or project archive.

---

## Phase 1 — Lock down current behavior with tests

1. Add unit tests for each incident-state transition.
2. Add tests for TTD/TTC calculations using fixed UTC timestamps.
3. Add tests for duplicate event IDs and out-of-order events.
4. Add an integration test covering:

```text
exercise start
-> malicious action
-> Wazuh alert
-> Blue Team investigation
-> containment
-> final report
```

5. Capture current scenario API responses as characterization fixtures.

**Exit condition:** The critical event and reporting behavior is reproducible before changing storage.

---

## Phase 2 — Introduce the canonical event contract

1. Create the Pydantic `StandardEvent` model.
2. Add `schema_version`, `room_id`, `run_id`, `incident_id`, `source`, and UTC `occurred_at`.
3. Generate JSON Schema from the model.
4. Add adapters for current Red Team, Wazuh mapper, and Blue Team payloads.
5. Validate every incoming event at one ingest endpoint.

**Exit condition:** All producers emit or are adapted into the same validated event format.

---

## Phase 3 — Unify persistence and incident state

1. Add SQLite migrations for events, incidents, rooms, runs, and memberships.
2. Implement `EventRepository` with a unique `event_id` constraint.
3. Implement the transition table and incident projection.
4. Temporarily dual-write to the old and new paths.
5. Compare resulting state and metrics in logs/tests.
6. Switch report endpoints to the new repository.
7. Remove the JSONL tail and both in-memory authoritative registries.

**Exit condition:** Red, Wazuh, and Blue events for one run appear in one ordered durable timeline and survive restarts.

---

## Phase 4 — Fix correlation before UI refactoring

1. Generate an incident/run identifier at exercise start.
2. Carry it through target execution and telemetry.
3. Map Wazuh alerts back to that identifier.
4. Use the attack trigger/start timestamp for TTD.
5. Store external IDs separately from ATTENSE IDs.

**Exit condition:** A complete exercise produces exactly one incident and one correct TTD/TTC timeline.

---

## Phase 5 — Choose and enforce one Blue Team topology

1. Keep one shared Blue Team API.
2. Remove embedded Uvicorn startup from the controller.
3. Remove dynamic Blue Team container creation and the build-only image service.
4. Require `room_id` and authorization on every Blue Team action.
5. Add cross-room isolation tests.

**Exit condition:** Two simultaneous rooms cannot read or modify each other's incidents while using the same service instance.

---

## Phase 6 — Consolidate scenarios and target routes

1. Define the scenario specification schema.
2. Migrate one scenario first and verify UI, execution, scoring, and reporting.
3. Migrate the remaining scenarios.
4. Serve scenario data through the API.
5. Delete hard-coded frontend/backend copies.
6. Merge guided/operator route implementations using mode policies.

**Exit condition:** Changing a scenario name, step, metric, or defense checkpoint requires editing one file only.

---

## Phase 7 — Simplify infrastructure

1. Split Compose into base/dev/security/AI files and profiles.
2. Remove fixed `container_name` values.
3. Create segmented networks.
4. Remove broad Docker socket mounts or add a restricted proxy.
5. Align Cassandra and Python versions.
6. Add health checks, resource limits, and log rotation.
7. Replace `chmod 777` with fixed ownership.
8. Use the production multi-stage frontend builds outside development.

**Exit condition:** A lightweight developer stack can start without TheHive/Cortex/Ollama, and the full stack starts predictably within a documented resource budget.

---

## Phase 8 — Delete verified legacy code

1. Run import/dependency analysis and coverage.
2. Remove the unused report generator.
3. Remove the inactive Nginx mapper or move it to an optional adapter package.
4. Remove port-pool migration remnants.
5. Remove the legacy shell path after confirming no frontend dependency.
6. Convert useful root scripts into tests; delete the rest.
7. Remove Supervisor from the Blue Team image.

**Exit condition:** Every remaining module has a documented owner, runtime caller, or test.

---

## Phase 9 — Add CI and acceptance gates

The CI pipeline should run:

1. Secret scan.
2. Python formatting and linting.
3. Type checking.
4. Frontend lint/build.
5. Unit tests.
6. Integration tests.
7. `docker compose config` validation.
8. Container vulnerability scan.
9. End-to-end smoke test.

Final acceptance checks:

- One incident contains attack, alert, investigation, containment, and end events.
- Event IDs are idempotent.
- State survives service restarts.
- TTD uses attack start, not completion.
- TTC uses the accepted containment action.
- Two rooms remain isolated.
- Scenario metadata has one source of truth.
- No active secrets are present in source or release archives.

---

# Priority Assessment

| Priority | Finding | Reason |
|---|---|---|
| **P0** | Secrets included in project archive | Immediate credential exposure risk |
| **P0** | Split incident registries | Can invalidate the project's central evaluation results |
| **P0** | Incident correlation mismatch | Can make attack and detection appear as separate incidents |
| **P1** | Flat network and Docker socket access | Weakens the security boundary of a cyber-range platform |
| **P1** | Conflicting Blue Team deployment models | Causes lifecycle, isolation, and ownership ambiguity |
| **P1** | Non-durable JSON/in-memory state | Restart loss and inconsistent reports |
| **P2** | Scenario duplication | High maintenance cost and scoring drift |
| **P2** | Compose and provisioning complexity | Slower development and fragile startup |
| **P3** | Frontend monoliths and legacy files | Maintainability and build-size issue |

# Final Architectural Recommendation

Do not begin by reorganizing folders. First unify the **event contract, correlation ID, persistence layer, and incident state machine**. Those four changes protect the validity of ATTENSE's core promise: objectively measuring how a Blue Team detects and contains the same attack executed by the Red Team.

After that foundation is stable, simplify deployment to shared stateless services with room-scoped data, consolidate scenario definitions, and split the infrastructure into optional profiles. This gives the project a smaller, more defensible architecture without removing the features required for the graduation demonstration.
