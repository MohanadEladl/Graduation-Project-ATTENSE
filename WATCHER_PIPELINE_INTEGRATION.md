# Watcher Agent + Report Pipeline — integration into the restructured architecture

Reference: `ATTENSE_Explainer_WatcherAgent_ReportPipeline.md` (component spec).
This component came from `feature/watcher-agent-webhook-pipeline`; the restructured
`main` predated it, so several pieces were missing or out of sync.

---

## 1. Structural changes made to align the old code with the new system's standards

1. **Pipeline relocated to the app-package layout.** `attense-app/pipeline/`
   (branch) → `apps/control-api/pipeline/` — sits beside `api/`, `core/`,
   `controller.py` and is importable as the top-level `pipeline` package its own
   modules expect (`from pipeline.bridge import ...`).

2. **Canonical event contract extended with the 5 v2.0.0 post-containment
   types.** `evidence_preserved`, `eradication_completed`, `recovery_validated`,
   `dismissal_approved`, `lessons_learned_recorded` were added to BOTH
   `attense_core/models/allowed_events.py` (`ALLOWED_EVENT_TYPES`) and
   `attense_core/models/constants.py` (`EventType`), kept in sync (the
   `test_event_types_match_allowed` gate enforces this). Without them the legacy
   `Event(...)` validator rejected the events the pipeline builds. They are
   scored by the pipeline, not incident state-machine transitions, so
   `incident.apply_event` correctly ignores them.

3. **Pipeline imports aligned to the canonical `attense_core` package** (not the
   legacy `ATTENSE_app.*` shims): `events.event → attense_core.models.event`,
   `incidents.incident → attense_core.models.incident`,
   `reports.report → attense_core.evaluation.reports`. `ATTENSE_app.AI.live_thresholds`
   is left as-is (the AI/threshold module is not part of `attense_core`).

4. **Restored `ATTENSE_app/AI/live_thresholds.py`** (dropped during the
   restructure; `bridge.py` imports `compute_live_thresholds`). The rule-data
   files it pairs with (`ATTENSE_app/AI/Data/APP-0X-*.json`) were already present.

5. **Restored the analyst-action ingestion endpoint.** The watcher POSTs to
   `POST /blueteam/analyst-action`; its router source was missing in the
   restructured blueteam (only a stale `.pyc` remained). Copied to
   `apps/blue-team-api/blueteam/api/analyst_actions.py` (fully self-contained — stdlib + fastapi +
   pydantic) and wired into `blueteam/main.py` (`include_router`). Now exposes
   `POST /blueteam/analyst-action` + `GET /blueteam/analyst-actions/{incident_id}`,
   persisting to `/attense/actions/<analyst_id>_<date>.jsonl` with 7-day retention.

**Verified:** `pipeline.bridge`/`scoring_engine` import; `blueteam.main` exposes the
2 analyst-action routes; canonical `Event` accepts the new types; 117 tests green
(106 ATTENSE_app + 11 blueteam isolation).

**Verified live, end-to-end, against the real running stack** (2026-06-23):
injected a Wazuh `alert_raised` event + 7 analyst-action events through the
actual `POST /blueteam/analyst-action` endpoint, then ran
`python -m pipeline.run_pipeline <incident_id>` inside the real `attense_app`
container. Full chain confirmed working: bridge merged both sources (8 events),
the real 9-rule scoring engine produced a correct score/verdict (rules timed
and evaluated against actual injected offsets), and the report was written to
`/attense/actions/<incident_id>_report.md`. Two real bugs surfaced and fixed
by this live run (neither was catchable from static analysis alone):

1. **`/attense/actions` had no writable directory.** `_append_to_disk()` in
   `analyst_actions.py` silently catches `OSError` and only logs a warning —
   so `POST /blueteam/analyst-action` always returned `201 {"ok": true}` even
   though the write was failing with `PermissionError` (`/attense` is
   `root:root` 755; the non-root `appuser` can't create a new subdirectory
   under it, and no Dockerfile step or volume ever created `/attense/actions`
   the way `/attense/data`/`/attense/temp` were). Fixed by adding
   `mkdir -p /attense/actions && chmod 777` to **both**
   `apps/control-api/Dockerfile` and `apps/blue-team-api/Dockerfile` (the
   standalone build carries the same code).
2. **`report_generator.py` crashed the whole module at import time** if
   `google-genai` wasn't installed (`from google import genai` at module
   level) — defeating the file's own documented contract ("falls back to a
   plain-text formatter... never exits on a Gemini error"). Root cause:
   `google-genai>=2.9.0` requires `pydantic>=2.12.5`, which conflicts with
   this project's pinned `pydantic==2.10.6` (load-bearing for the
   `StandardEvent` contract and all 138 tests) — so it can't simply be added
   to `requirements.txt`. Fixed by making the import lazy (`try`/`except
   ImportError`, `_GENAI_AVAILABLE` flag), so a missing package now degrades
   to the plain-text fallback exactly like a missing `VERTEX_PROJECT_ID` does
   — never a crash.

---

## 2. Integration steps to wire this component back into the main architecture

**Done (in this repo, verified live against the running stack):**
- Pipeline package placed + imports aligned to `attense_core` (imports cleanly).
- Event contract extended; `Event(evidence_preserved, …)` validates.
- `live_thresholds.py` restored; rule data present.
- `/blueteam/analyst-action` router restored and wired into the blueteam app —
  confirmed live: returns real `201`s, persists to disk, and `bridge.py` reads
  them back correctly.
- `apps/control-api/Dockerfile` now `COPY`s `pipeline/` and
  `packages/attense-core` into the image (added during the folder restructure
  — see `MIGRATION.md`), so the aligned `attense_core.*` imports and
  `pipeline.*` resolve in-container, not just on the host.
- `/attense/actions` permission fix (both Dockerfiles) and the lazy
  `google-genai` import (`report_generator.py`) — see above.
- `python -m pipeline.run_pipeline <incident_id>` runs to completion inside
  the real container and writes a real report file.

**Remaining (need external deps/credentials, not just the stack):**
1. **Live Gemini** — `google-genai` is deliberately NOT installed (the
   pydantic conflict above), so the pipeline always uses the plain-text
   fallback today. Getting real Gemini output needs either a pydantic bump
   (project-wide, out of scope) or pinning an older `google-genai` release
   compatible with `pydantic<2.12.5` (not checked) — plus
   `VERTEX_PROJECT_ID`/real GCP credentials either way.
2. **Watcher agent** — `watcher/` runs on the analyst's **Linux** host (auditd),
   not a container. It's in the worktree; copy `watcher/` into this repo if you
   want it tracked here. Point it at `BLUETEAM_URL=http://<host>:8010` (the
   analyst-action endpoint, now served) and `COORDINATOR_URL=http://<host>:8000`
   (red-team-api backend). Watcher names map to canonical via
   `bridge.ANALYST_EVENT_MAP` (`investigation_started → alert_investigation_started`).
3. **Run the pipeline** — `python -m pipeline.run_pipeline <incident_id>` inside
   control-api; set `VERTEX_PROJECT_ID` / `VERTEX_MODEL` / `VERTEX_LOCATION` +
   `gcloud auth application-default login` for Gemini.
4. **Data paths** — `bridge.py` reads `/attense/data/mapped_events.jsonl`
   (signal-mapper output) and `/attense/actions/analyst-*.jsonl` (analyst-action
   router output); both already exist as volumes — no compose change needed.
5. **Blueteam topology** — the analyst-action endpoint lives in the blueteam app;
   in the current deploy that's the embedded copy in control-api on `:8010` (the
   watcher's default). Revisit when the Phase 5 blueteam topology cutover is decided.

**Optional further alignment (not required to run):** `bridge.py` rebuilds an
`Incident` from JSONL by hand, duplicating the Phase 3 `EventRepository` /
`IncidentProjection`. It could read from the durable store instead; left as-is to
preserve the pipeline's verified behaviour.
