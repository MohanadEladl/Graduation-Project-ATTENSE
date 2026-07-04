# Red Team — Guided Mode Is Reading-Only

## 1. Branch and commit tested

- **Branch:** `feature/attacker-activity-log`
- **Base commit:** `0fad13e`

## 2. Why Guided Mode is reading-only

Guided Mode used to be an "easy" version of the lab: it counted evidence from
any channel (including plain browser clicks against `/auth/login`, `/search`,
`/files/read`, `/system/ping`, `/profile/`) and could mark a mission complete,
generate an AI report, and show a "View Report" button — all without ever
touching ZAP, the AttackBox, or the `/op/` operator surface.

That blurred the product's real teaching goal. The updated contract:

> Guided Mode is educational reading/tutorial guidance only. Operator Mode is
> the only mode that runs the actual lab pipeline.

Guided Mode still explains the concept, the vulnerable pattern, and the
defense — it just never pretends a real attack happened.

## 3. Guided vs Operator — the contract

```text
Guided Mode:
- Reading/tutorial only.
- No attack execution.
- No evidence-based mission completion.
- No target-agent evidence scoring.
- No AI attack report required.
- Static tutorial content, concepts, diagrams, examples, defensive explanation.
- "Mark as read" (local-only) or "Continue to Operator Mode" — never
  "attack completed".

Operator Mode:
- Actual lab.
- Uses /op/... target routes.
- Uses ZAP / AttackBox / approved evidence.
- Uses objective-based completion.
- Uses quality scoring.
- Generates AI/Purple report.
```

The wire value for Guided Mode is still `"tutorial"` (frontend/session
compatibility); Operator Mode is still `"lab"`. Only the *behavior* changed —
call sites and comments were updated to describe them as "guided
(reading-only)" and "operator (lab)" throughout.

## 4. What backend code was removed / changed

**`red-team/backend/lab_progress.py`**
- Removed `tasks_tutorial` and `success_tutorial` from all 7 `PROGRESS_SPECS`
  module entries — dead data once Guided Mode stopped scoring evidence.
  `tasks_lab` / `success_lab` / `defensive_insight` are kept (Operator Mode's
  legacy, non-variant task ladder).
- **`compute()` now short-circuits for `mode="tutorial"` (guided) before any
  event is fetched or evaluated**, via `_guided_reading_only_response()`. This
  is the core change: Guided Mode literally never calls `fetch_events()`,
  never runs the evidence gate, never computes a score.
- `_event_counts_for_mode()`'s guided branch changed from "any channel counts"
  to `return False` unconditionally — defense-in-depth, since the short-circuit
  above means this is now unreachable in the live code path, but the function
  itself no longer has a permissive guided behavior if ever called directly.
- Simplified the now-dead `is_lab`-ternary task-ladder/success-key logic (both
  always resolved to the lab branch once Guided Mode short-circuits earlier).

**`red-team/backend/main.py`**
- `/api/sessions/{sid}/check-progress` — docstring clarified; behavior flows
  automatically from `compute()`'s short-circuit (no separate change needed).
- `/api/sessions/{sid}/report` — now returns a short reading-only message for
  guided-mode sessions (`GUIDED_MODE_REPORT_MESSAGE`) instead of generating an
  attack report, *before* touching the timeline/lab-events/report-agent
  machinery. `regenerate_report` inherits this via `get_report()`.

**`red-team/backend/session_manager.py`**
- `SessionManager.execute()` now refuses guided-mode sessions
  (`GUIDED_MODE_EXECUTE_DISABLED_MESSAGE`) **before** checking the
  instructor/demo `ENABLE_AUTO_ATTACKS` flag — Guided Mode cannot run scripted
  module execution under any configuration. Operator Mode's existing
  auto-attacks gate (disabled by default) is unchanged.

**`red-team/backend/report_agent.py`**
- `generate()` refuses to synthesize an attack report for `mode="tutorial"`
  (defense-in-depth; `main.py`'s `/report` endpoint already intercepts this).

**`apps/target-lab/app/main.py`**
- Added a classification comment at the blueprint-registration point: the
  non-`/op/` routes (`/auth`, `/search`, `/files`, `/system`, `/profile`,
  `/`) are demo/legacy surfaces, kept online for instructor use, but **never**
  scored — no Red Team mission completion is derived from them anymore.
  `/op/...` routes remain the only scored Operator Mode surface. No routes
  were deleted (per instructions — not proven unused, just reclassified).

## 5. What frontend behavior changed

`red-team/frontend/src/routes/Workspace.jsx`:
- **`GuidedWalkthrough`** (the sidebar component rendered inside the
  hands-on 3-column layout during a Guided-mode Mutation run — the one edge
  case where `LearningPanel` still renders in tutorial mode) no longer shows
  a live "WALKTHROUGH" progress bar or per-task auto-tracking checklist.
  It now renders the concept overview plus a static "READING-ONLY" notice
  pointing at the Operator Mode switch. The dead `WalkthroughTask` component
  (only used by the old evidence-tracking checklist) was removed.
- **`MissionSidebar`**'s "PROGRESS" bar is now Operator-Mode-only; Guided
  Mode shows a "GUIDED MODE · READING-ONLY" label instead of a stale 0%
  progress bar. The timer/elapsed display is unchanged for both modes.
- The primary Guided Mode experience — **`GuidedRoom`** (a full-width,
  session-less reading room fetched from the static
  `/api/modules/{id}/walkthrough` endpoint, with `localStorage`-only
  "MARK COMPLETE" toggles and a "Switch to OPERATOR MODE" hand-off) — was
  **already** fully compliant with the new contract before this change; it
  required no modification.
- `MissionCompleteSummary` / the "View Report" banner were already gated on
  `progress.success`, which is now always `false` for Guided Mode — so they
  stop appearing in Guided Mode automatically, with no code change needed
  there.

`red-team/frontend/src/routes/MissionReport.jsx`:
- Added a `report.reading_only` guard that renders a plain "Guided Mode is
  reading-only" message instead of attempting to render the full report UI
  (which expects grade/score/evidence fields a guided session never has).
  This protects against stale pre-migration sessions that may still have
  `learning_state === "completed"` in persisted session storage.

`red-team/frontend/src/routes/Reports.jsx`:
- The "VIEW REPORT" button is now shown only for Operator (`lab`) sessions,
  so a stale guided session sitting in the completed-sessions list can't
  offer a report it will never receive.

`red-team/frontend/src/data/missionBriefings.js`: reviewed against the
prohibited phrasing list ("complete the guided attack", "trigger guided
evidence", "guided mission success") — **none of it was present**. The
tutorial content already reads as concept/methodology narrative
(`concept` / `why` / `tryIt` / `lookFor` / `observe`), and the
`successCondition` field is metadata that was never rendered anywhere in the
UI. No changes were needed to this file; `tutorialStepsFor()`, `operatorHints`,
objectives, and target-path helpers are all unchanged and still used exactly
as before.

## 6. How Operator Mode completion still works

Unchanged from the objective-based-progress work (see
`docs/redteam-objective-based-progress.md`): completion is objective-based
(reaching the real attack target through the `/op/` operator surface via an
approved tool), quality is scored separately and never blocks completion,
ignored-evidence diagnostics explain why unqualified evidence didn't count,
and the CSRF browser-lure exception remains scoped to CSRF only.

## 7. Tests run

`pytest red-team/backend/tests -q` → **160 passed**.

- **New: `test_guided_reading_only.py`** (26 tests) — the full Guided Mode
  contract: `reading_only=True` + `success=False` + zero scores + empty
  tasks/evidence for every module and both wire values (`tutorial`,
  `guided`); a hard assertion that `fetch_events()` is never called in
  Guided Mode; guided/operator evidence presence never changes the (always
  negative) outcome; the full API shape (all diagnostic fields, including
  every `ignored_reasons` bucket) is present even with no events;
  `SessionManager.execute()` refuses guided-mode execution even when
  `ENABLE_AUTO_ATTACKS=true` (and confirms Operator Mode's existing gate is
  untouched); `report_agent.generate()` refuses to synthesize a guided-mode
  report.
- **Updated: `test_operator_gating.py`** — replaced the two tests that
  asserted the now-removed behavior
  (`test_tutorial_completes_with_guided_browser_evidence`) with
  `test_tutorial_never_completes_even_with_guided_browser_evidence` /
  `..._operator_evidence`, proving reading-only holds regardless of evidence
  shape.
- **Unchanged and still green**: all Operator Mode objective-completion,
  quality-scoring, ignored-diagnostics, CSRF-exception, and brute-force
  strict-logic tests (Part 9.B/C) — none of that code path was touched.

No JavaScript test runner exists in this repo (`package.json` only defines
`dev`/`build`/`preview`; no `test`/`lint` script, no jest/vitest config), so
frontend behavior (Part 9.D) was verified by code review — confirming the
`success`-gated banners now flow from a backend guarantee rather than
Guided-Mode evidence, plus a successful production build — not by an
automated JS test suite.

## 8. Remaining risks

- **Stale persisted sessions**: sessions created before this change may have
  `mode="tutorial"` with `learning_state="completed"` / `learning_success=true`
  already written to `/tmp/attense_sessions.json`. They will still list in
  `Reports.jsx` until that file is cleared (survives restarts, cleared on
  `docker rm`), but their "VIEW REPORT" button is now hidden and `/report`
  now safely returns the reading-only message instead of a fabricated report.
- **Mutation Mode + Guided sub-mode**: Mutation Mode sessions
  (`mutation_mode=true`) can still be started in "tutorial" sub-mode, which
  renders the 3-column lab layout with the updated (now reading-only)
  `GuidedWalkthrough` rather than the full-width `GuidedRoom`. This is an
  existing, narrow feature interaction that was not otherwise touched or
  retested end-to-end.
- **No JS test runner**: frontend correctness for Part 9.D rests on code
  review + a successful build, not automated assertions.
- The Docker manual smoke test (Part 13) was not executed in this session —
  see the final response for what could/couldn't be verified.

## 9. Final verdict

**GREEN (code)** — Guided Mode's backend lab-execution/progress logic is
removed; `compute()` for guided/tutorial mode is a pure, static,
reading-only response with zero event fetching; scripted execution and
report generation are both blocked for guided sessions at every layer
(lab_progress, session_manager, report_agent, main.py); Operator Mode is
completely unchanged and still fully tested. **AMBER (runtime)** pending the
manual Docker walkthrough, which is an environment step outside this change.
