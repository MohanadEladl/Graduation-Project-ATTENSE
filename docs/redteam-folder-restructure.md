# Red Team Folder Restructure

## Why

The Red Team code lived in a single root folder (`red-team/`) mixing backend
and frontend concerns in one tree, unlike every other service in the repo
(`apps/*` + `frontends/*`). This split brings Red Team in line with that
convention — matching the layout already used on `main` for
`apps/red-team-api/` and `frontends/red-team/` — so backend and frontend own
separate build contexts, dependency files, and test suites.

This was a pure move: no Red Team logic, objective-based progress model,
Operator Mode gating, ZAP Workspace, AttackBox safety validation, or
report-agent behavior was changed. Only file locations, import/path
assumptions, Docker/compose contexts, and doc references were updated.

## Old structure

```text
red-team/
├── backend/        FastAPI app, tests/
├── core/            Base module + models
├── engine/           Session state machine
├── modules/          7 attack modules
├── ollama/           MITRE-analyst Modelfile + build script
├── scripts/          pull_ollama_model.sh
├── frontend/         React + Vite UI
├── Dockerfile
├── requirements.txt
└── main.py           CLI fallback
```

## New structure

```text
apps/red-team-api/
├── backend/          FastAPI app, tests/ (moved with backend/)
├── core/
├── engine/
├── modules/
├── ollama/
├── scripts/
│   ├── pull_ollama_model.sh
│   └── redteam_cli.py   (formerly red-team/main.py — debug/CLI only)
├── Dockerfile
└── requirements.txt

frontends/red-team/
├── src/
├── public/
├── package.json
├── package-lock.json
├── vite.config.js
├── postcss.config.js
├── tailwind.config.js
├── index.html
├── nginx.conf
├── Dockerfile
└── .dockerignore
```

The old `red-team/` root folder has been deleted. `git status` and
`git ls-files red-team` confirm no tracked files remain there; the only
leftover on disk before deletion was gitignored build/runtime output
(`node_modules/`, `dist/`, `__pycache__/`, `.pytest_cache/`, `logs/`), which
regenerates on the next `npm install` / `docker compose build`.

## Why `main.py` became `scripts/redteam_cli.py`

Its own docstring already said it was a CLI fallback for SSH/debugging — the
primary interface is the browser shell. Per the plan's guidance for
debug-only entrypoints, it moved to `scripts/redteam_cli.py` with an updated
docstring making that explicit. Its `sys.path` bootstrap now resolves the
service root via `Path(__file__).resolve().parents[1]` instead of its own
directory, since `core/`/`modules/` are one level up from `scripts/` now.
`discover_modules("modules")` was left untouched — `core/module_loader.py`
already resolves `modules/` relative to its own `__file__`
(`Path(__file__).resolve().parent.parent / package_path`), so it was already
independent of both the caller's CWD and the July move; passing an absolute
path there would have broken the `importlib.import_module` call, since the
same string doubles as the dotted import path.

## Backend source of truth (unchanged locations, moved as a unit)

- Progress: `apps/red-team-api/backend/lab_progress.py`
- Operator evidence gating: `apps/red-team-api/backend/operator_api.py`
- Reports: `apps/red-team-api/backend/report_agent.py`
- Chain metadata: `apps/red-team-api/backend/chain_engine.py`
- Mutation catalog: `_MUTATION_CATALOG` in `apps/red-team-api/backend/main.py`

## Frontend source of truth

- `frontends/red-team/src/data/missionBriefings.js`
- `frontends/red-team/src/routes/Workspace.jsx`
- `frontends/red-team/src/routes/MissionReport.jsx`

## Docker / compose updates

`infra/compose.base.yml`:

```yaml
red-team-backend:
  build:
    context: ../apps/red-team-api      # was ../red-team
red-team-frontend:
  build:
    context: ../frontends/red-team     # was ../red-team/frontend
```

Service names (`red-team-backend`, `red-team-frontend`), container names,
ports, env vars, and internal container paths (`/red-team/...` inside the
image, `PYTHONPATH=/red-team`) were left untouched — those are internal to
the image, not host source paths, so changing them wasn't required and would
have added risk for no benefit.

`apps/red-team-api/Dockerfile`: `COPY main.py ./main.py` replaced with
`COPY scripts/ ./scripts/` (the CLI now lives under `scripts/`).

`.github/workflows/ci.yml`: the `frontend-build` matrix's `red-team` entry
now points at `frontends/red-team` (previously `red-team/frontend`, with a
comment noting `frontends/red-team` "does not exist" — it does now).

## Tests moved and fixed

`red-team/backend/tests/*` moved to `apps/red-team-api/backend/tests/*` as
part of the `backend/` directory move. Five test files computed a repo-root
`Path(__file__).resolve().parents[N]` for cross-referencing frontend source
or sibling services; the extra `apps/red-team-api/` nesting level shifted
every one of those by one parent, so each was corrected:

| File | Old | New |
|---|---|---|
| `test_student_safety.py` | `ROOT = parents[3]`, `ROOT/"red-team"` | `SERVICE_ROOT = parents[2]`, `ROOT = parents[4]`, paths via `frontends/red-team` and `SERVICE_ROOT` |
| `test_frontend_wiring.py` | `ROOT = parents[3]`, `FE = ROOT/"red-team"/"frontend"` | `ROOT = parents[4]`, `FE = ROOT/"frontends"/"red-team"` |
| `test_guided_reading_only.py` | `ROOT = parents[3]`, `sys.path` via `ROOT/"red-team"` | `SERVICE_ROOT = parents[2]` |
| `test_objective_progress.py` | same pattern | same fix |
| `test_operator_gating.py` | same pattern | same fix |
| `test_target_evidence.py` | `TARGET_APP = parents[3]/"apps"/"target-lab"/"app"` | `parents[4]/...` |

These were real bugs the move would have introduced (wrong `ROOT`, so
`sys.path` insertion and `Path.read_text()`/`.exists()` calls in the moved
tests would have silently pointed at `apps/` instead of the repo root). All
were caught and fixed before the test run, not discovered by a failure.

Historical/prose-only path references (comments in `attackbox/Dockerfile`,
`apps/target-lab/app/main.py`, `scripts/verify_target_op.py`) were updated to
the new paths for accuracy; they had no functional effect either way.

## Docs updated

`README.md` (architecture file list + project layout tree),
`docs/MODULE_PLAYBOOK.md`, `docs/redteam-objective-based-progress.md`,
`docs/redteam-guided-mode-reading-only.md`,
`docs/redteam-all-modules-portswigger-alignment.md`,
`docs/redteam-bruteforce-zap-test-report.md`, and
`docs/redteam-cleanup-audit.md` now reference `apps/red-team-api/...` and
`frontends/red-team/...` instead of `red-team/backend/...` /
`red-team/frontend/...`.

Point-in-time historical documents (`CHANGELOG_v6.md`, `CHANGELOG_v7.md`,
`CHANGELOG_v8.md`, `PROGRESS.md`, `HEARTBEAT.md`, `QA_FULL_TEST_REPORT.md`,
`MIGRATION.md`, `ATTENSE_Refactoring_Optimization_Report.md`,
`docs/DOCKER_MULTISTAGE_HARDENING.md`, `docs/session_mitre_module_rework.md`,
`docs/superpowers/plans/2026-05-26-mutation-timeline-report.md`) still
reference the old `red-team/` paths. These are dated snapshots of past
states (like git log entries) — rewriting them would misrepresent what was
actually true at the time they were written, so they were intentionally left
as historical record rather than updated.

## Test commands (new)

```bash
python -m compileall apps/red-team-api/backend apps/target-lab/app
pytest apps/red-team-api/backend/tests -q
cd frontends/red-team && npm install && npm run build
docker compose config
```

## Verification performed

- `python -m compileall apps/red-team-api/backend apps/target-lab/app` — clean.
- `pytest apps/red-team-api/backend/tests -q` — **161 passed**, 0 failed.
- `npm install && npm run build` in `frontends/red-team/` — succeeds (2814 modules).
- `docker compose config` — valid; `red-team-backend` and `red-team-frontend`
  build contexts resolve to `apps/red-team-api` and `frontends/red-team`.
- `docker compose build red-team-backend red-team-frontend` — both images
  build successfully with the new contexts (backend picks up the
  `COPY scripts/` fix; frontend Dockerfile needed no changes).
- `docker compose up -d red-team-backend red-team-frontend` (with dependency
  chain: target-agent, attackbox, ollama, check-secrets, etc.) — all four
  core containers reported `healthy`.
  - `GET http://localhost:3000/` → 200 (frontend loads).
  - `GET http://localhost:3000/frontend-health` → `ok`.
  - `GET http://localhost:3000/health` → 200 (backend health, proxied).
  - `GET http://localhost:3000/api/modules` → all 7 modules returned with
    MITRE metadata, proving `discover_modules()` correctly loads
    `apps/red-team-api/modules/` at container runtime, not just at
    `compileall` time.
  - Stack was brought back down (`docker compose down`) after verification
    since it was started solely for this check.
- Path sanity greps: no remaining `red-team/backend`, `red-team/frontend`,
  `pytest red-team/backend`, or `cd red-team/frontend` outside the
  intentionally-untouched historical docs listed above.

## Could not be tested

- Full interactive UI smoke test (clicking through Guided Mode reading room,
  launching Operator Mode, opening ZAP Workspace, using the AttackBox
  terminal, completing the XSS Operator objective end-to-end, opening a
  Mission Report) — this environment has no browser-driving tool available.
  The runtime checks above (container health, module discovery via
  `/api/modules`, proxied health checks) substitute for build/wiring
  correctness but do not exercise the browser UI itself.
- The pre-existing `tests/integration/red-team-api` directory referenced in
  `.github/workflows/ci.yml` (line ~67) does not exist in the working tree.
  This predates the restructure and is unrelated to it — left untouched.

## Remaining risks

- The five test files whose `parents[N]` math changed are the highest-risk
  spot for a future move: if `apps/red-team-api/backend/tests/` moves again,
  every one of those constants needs re-deriving by hand (no test currently
  asserts the constant itself, only its effects).
- Historical docs listed above still show `red-team/...` examples; a reader
  skimming those without noticing they're dated could copy a stale path.
