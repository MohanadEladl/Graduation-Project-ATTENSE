# QA — `refactor/restructure-and-pipeline-integration` branch

**Date:** 2026-06-29
**Branch tip:** `acdb4e6` "Refactor: restructure codebase and integrate pipeline"
**vs current HEAD `5bb99ae`:** 80 commits ahead / 10 behind · **492 files, +28,595 / −6,319**
**How tested:** isolated `git worktree` at `../restructure-test` (running stack & working
tree left untouched). Replicated the CI `python-tests` + `compose-config` jobs locally
(Python 3.12.10 venv, deps per `.github/workflows/ci.yml`).

## New structure
Monorepo: `apps/` (blue-team-api, control-api, event-api, red-team-api, signal-mapper,
**target-lab**, **watcher**, **zeroday-agent**), `frontends/` (blue-team, portal, red-team),
`integrations/` (cortex, thehive, wazuh), `infra/` (layered compose: base/security/ai/dev),
`packages/attense-core`. Focus of the refactor: blue-team scoring pipeline (R01–R09 engine),
Gemini/Vertex report path (`google-genai` SDK), and a new zero-day detection agent.

## Automated test results — ✅ 163/163 passing
| Suite | Result |
|---|---|
| `tests/unit` (pure domain logic) | **94 passed** |
| `tests/integration/control-api` (persistence, correlation, scenarios API) | **32 passed** (in-process Starlette client; stray offline-simulator log noise) |
| `tests/integration/blue-team-api` (cross-room isolation) | **11 passed** |
| `tests/integration/red-team-api` (TTD anchor + event contract) | **2 passed** |
| `tests/integration/signal-mapper` (Wazuh correlation) | **6 passed** |
| `tests/zeroday_agent` + MITRE scanner + mapper-suitability | **18 passed** |
| `docker compose config -q` (merges infra/compose.*.yml, 23 services) | **VALID** |

MITRE relevance: `tests/zeroday_agent/test_mitre_attack.py` verifies the new agent's
keyword scanner maps log lines to ATT&CK techniques (T1595 Active Scanning, T1110 Brute
Force, etc.) and returns no false positives on benign lines. All green.

## Carry-over defect (unchanged in this branch)
**Mutation Mode still not wired** — `apps/target-lab` has no `/lab/mutations/*` endpoints
and no per-route enforcement (`get_flat_active_for_request` unused). The red-team-api still
ships `_MUTATION_CATALOG`. Same defect as the current branch; the refactor did not address it.

## Not yet run (need live stack / external credentials)
- **e2e smoke** (`tests/e2e` is a README placeholder) — boots the full stack.
- **Full live stack bring-up** of the 23-service topology + re-running the live
  attack/gauntlet/mutation tests against renamed services (`red-team-api`, `target-lab`).
  Requires tearing down the currently-running old stack.
- **Gemini/Vertex report path & zeroday-agent live inference** — need
  `gcloud auth application-default login` (GCP ADC) credentials.
- **frontend-build** (`npm ci && npm run build` for 3 frontends) — not yet run.
