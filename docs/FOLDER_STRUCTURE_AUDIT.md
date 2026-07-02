# Folder Structure Audit

This audit separates real duplication from intentional service boundaries. After the cleanup, `packages/attense-core/attense_core` is the canonical shared ATTENSE domain package. The old `apps/control-api/ATTENSE_app` tree has been removed, and services now import or mount/copy `attense_core` directly.

## Top-Level Ownership

| Path | Role | Cleanup decision |
| --- | --- | --- |
| `apps/` | Runtime backend services and agents. | Keep. Each child is a deployable or runnable component. |
| `frontends/` | Browser apps served by Vite/nginx. | Keep. Do not mix frontend sources into backend services. |
| `packages/attense-core/` | Canonical shared ATTENSE domain package. | Keep as the single source for shared models, repositories, evaluation, and scenario data. |
| `tests/` | Repo-level unit, integration, and e2e acceptance tests. | Keep. Service-local tests can remain when tightly scoped. |
| `infra/` | Compose and database infrastructure. | Keep. Runtime service definitions belong here. |
| `integrations/` | External integration config/bootstrap assets for TheHive, Cortex, Wazuh. | Keep. Do not merge into app source. |
| `scripts/` | Bootstrap, healthcheck, and maintenance tooling. | Keep. Audit tooling lives under `scripts/maintenance/`. |
| `docs/` | Architecture, status, and audit documents. | Keep. Store cleanup rationale here. |
| root generated artifacts | Local Designer/codegen/test outputs. | Ignore by default; remove only after confirming they are not user deliverables. |

## Repetition That Is Intentional

| Repeated shape | Why it exists | Decision |
| --- | --- | --- |
| `apps/*/api`, frontend `src/api` | Different API layers: backend routers vs frontend HTTP clients. | Keep. Same name, different responsibility. |
| `apps/*/core` | Service-owned business logic for separate bounded contexts. | Keep unless code becomes truly shared. |
| `apps/*/tests` and top-level `tests/*` | Service-local tests plus repo-level acceptance tests. | Keep. Prefer top-level tests for cross-service behavior. |
| `apps/*/app` | FastAPI/Flask app packages for services with generic app layout. | Keep. No cleanup needed just because names match. |
| `integrations/thehive` and Blue Team TheHive infrastructure code | Config/bootstrap assets vs runtime client code. | Keep. Different ownership. |

## Removed Legacy Duplication

| Removed legacy path | Canonical replacement | Current status |
| --- | --- | --- |
| `apps/control-api/ATTENSE_app/events` | `packages/attense-core/attense_core/models` | Deleted after import migration. |
| `apps/control-api/ATTENSE_app/incidents` | `packages/attense-core/attense_core/models` | Deleted after import migration. |
| `apps/control-api/ATTENSE_app/persistence` | `packages/attense-core/attense_core/repositories` | Deleted after import migration. |
| `apps/control-api/ATTENSE_app/reports`, `matrics`, `Outcomes` | `packages/attense-core/attense_core/evaluation` | Deleted after import migration. |
| `apps/control-api/ATTENSE_app/AI/Data` and `AI/live_thresholds.py` | `packages/attense-core/attense_core/evaluation/attack_data`, `live_thresholds.py`, `attack_rules.py` | Moved into the canonical package. |
| `apps/control-api/ATTENSE_app/Scenarios` | `packages/attense-core/attense_core/scenarios/data` | Deleted; scenario tests now target the canonical package. |

## Why `attense_core` Still Appears In Many Places

`attense_core` is no longer duplicated as source code. It appears in Dockerfiles and Compose mounts because every container has its own filesystem. During image builds, services copy the package into `/app/attense_core`; during development, Compose bind-mounts the same host package into the container so reload uses local changes. Those are deployment references to one source tree, not separate code copies in the repo.

## Remaining Cleanup Candidates

| Candidate | Current finding | Decision for this pass |
| --- | --- | --- |
| root `*.dc.html`, `support.js`, `.thumbnail` | Generated Designer/runtime preview output; no repo references found. | Ignore rules added. Do not delete automatically. |
| root `assets/`, `uploads/`, `test_logs/` | Local/runtime artifacts; no tracked references found for root-level paths. | Ignore rules added. Keep service-owned `frontends/*/assets` untouched. |
| root `test_full_cycle.py` | Manual live-stack diagnostic script, not imported by tests. | Ignore as local scratch for now; later move to `tests/e2e/` if it should be tracked. |
| `frontends/red-team/_shot*` | Local screenshot/debug artifacts. | Ignore rules added. |
| `frontends/red-team/src/data/missionBriefings.js` | Hard-coded mission/scenario copy. | Later migration: load canonical scenario data from Control API. |
| `apps/target-lab/app/routes` and `routes_op` | Guided vs operator route split. | Later migration: merge behind mode/profile policy after tests. |

## Cleanup Rules

1. Never delete a tracked folder only because its name repeats elsewhere.
2. Before removal, search imports, Dockerfile `COPY`, compose mounts, frontend references, tests, and docs.
3. Shared ATTENSE domain code belongs in `packages/attense-core/attense_core`.
4. Generated artifacts should be ignored, not committed.
5. Service-local `core` folders stay service-local unless there is repeated behavior that should become shared package code.

## Follow-Up Order

1. Run `python scripts/maintenance/audit_structure.py` before and after cleanup work.
2. Keep new shared model/evaluation/repository code in `packages/attense-core/attense_core`.
3. Replace frontend hard-coded scenario data with `/api/scenarios` in a dedicated feature branch.
4. Merge target-lab guided/operator routes only after route-level tests describe both modes.
5. Remove stale documentation references to old paths as they are encountered.