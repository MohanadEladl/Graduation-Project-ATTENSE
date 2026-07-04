# Red Team Cleanup Audit

## Dependency Scan

The required pre-delete dependency scan was saved to:

`C:\tmp\redteam-cleanup-dependency-scan.txt`

The scan showed that the legacy Attack Report and Lab Analysis paths were still wired only through their own frontend/backend route pairs, while the current student report flow already uses `MissionReport.jsx` and `/api/sessions/{sid}/report`.

## Removed

- Removed `red-team/frontend/src/routes/AttackReport.jsx`.
- Removed `red-team/backend/lab_analysis.py`.
- Removed the `/api/sessions/{sid}/attack-report` endpoint.
- Removed the `/api/sessions/{sid}/lab-analysis` endpoint.
- Removed `api.sessions.getAttackReport`.
- Removed `api.sessions.labAnalysis`.
- Removed `LabAnalysisSection` from `Reports.jsx`.
- Removed rigid briefing exports from `missionBriefings.js`:
  - `LAB_STEPS_BY_MODULE`
  - `REQUIRED_TOOLS_BY_MODULE`
  - `labStepsFor`
- Removed hardcoded Gauntlet chain definitions from `CHAIN_META` / `CHAIN_ORDER`.
- Removed the unused Gauntlet mutation definition table and expandable mutation card path.
- Removed detailed `DEFENSE_DETAILS` duplication from `Workspace.jsx`.

## Kept

- `red-team/main.py` was kept because the Dockerfile still copies it and its docstring already labels it as a CLI fallback/debug interface. The container entrypoint remains `uvicorn backend.main:app`.
- `red-team/core/`, `red-team/engine/`, and `red-team/modules/` were kept because module discovery and debug/scripted-demo support still depend on them.
- `red-team/modules/README.md` now documents the active metadata plus legacy scripted-demo split that should happen in a future refactor.
- The instructor-only automated execution endpoint stayed in place because it is still gated by `ENABLE_AUTO_ATTACKS=false` by default and is separate from the removed legacy Attack Report route.

## Sources Of Truth

- Progress: `red-team/backend/lab_progress.py` remains the objective-based progress source. Methodology events remain quality signals rather than rigid completion blockers.
- Operator evidence: `red-team/backend/operator_api.py` remains the strict source for `/op/` route validation, `backend=operator`, approved `via` values, and AttackBox command safety.
- Reports: `red-team/backend/report_agent.py` and `/api/sessions/{sid}/report` are the active learning/report source. `MissionReport.jsx` remains the frontend report path.
- Chain metadata: `red-team/backend/chain_engine.py` is the source for chain IDs, names, descriptions, and phase order. `Gauntlet.jsx` now fetches `api.chains.list()` and `api.chains.get()`.
- Mutation catalog: `_MUTATION_CATALOG` in `red-team/backend/main.py` is the source for mutation availability. A sanitized read-only `/api/mutations/catalog` endpoint exposes public labels/counts without solution-oriented target tasks.
- Defense guidance: detailed defensive recommendations remain in `report_agent.py`; Workspace only shows brief mitigation content already present in mission briefings.

## Safety Notes

- AttackBox validation was not weakened.
- External target blocking was not loosened.
- `/op/` Operator evidence rules were not changed.
- Browser-only completion rules were not changed.
- `via=unknown` completion rules were not changed.
- Legacy rigid checklist exports were removed instead of replacing backend objective gates.

## Tests And Checks

Passed:

- `node --check red-team/frontend/src/data/missionBriefings.js`
- `C:\Users\Yousof\AppData\Local\Programs\Python\Python312\python.exe -m compileall red-team\backend apps\target-lab\app`
- `C:\Users\Yousof\AppData\Local\Programs\Python\Python312\python.exe -m pytest red-team\backend\tests -q` (`134 passed`)
- `cd red-team/frontend && npm install`
- `cd red-team/frontend && npm run build`
- `docker compose config`

Notes:

- The frontend package has no `lint` script, so `npm run lint` was not available.
- `node --check` cannot directly parse `.jsx` files in the current Node setup, so JSX syntax was covered by the Vite build.
- The local PowerShell PATH did not resolve bare `python`; the checks used the resolved Python 3.12 executable path directly.

## Remaining Cleanup Candidates

- Split `red-team/modules/` into metadata and scripted-demo directories in a dedicated refactor.
- Consider moving the instructor-only auto-run endpoint under an explicit instructor namespace if the product keeps it long term.
- Expand `_MUTATION_CATALOG` only when backend/target support actually exists; the Gauntlet UI now filters to backend-supported mutation modules.
- Review historical root reports/docs separately before deleting them; some are audit artifacts rather than active product instructions.
