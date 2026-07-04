# Red Team — Objective-Based Progress (Completion vs Quality)

## Why the progress model changed

Operator Mode previously felt too procedural: a lab could be finished with one
correct action (e.g. a single reflected-XSS payload), yet the panel still read as
an ordered checklist the student had to clear step by step. That framing punished
students who reached the real objective efficiently and made instructor demos
feel scripted.

The model now **separates mission completion from learning quality**:

- **Completion** depends only on reaching the actual attack objective through the
  approved channel. One correct action can complete the mission.
- **Quality** scores the recommended methodology (capture → inspect → Repeater →
  compare → confirm). It is advisory: skipping it lowers the quality score and
  shows up as report coaching, but it **never blocks completion**.
- **Safety** is unchanged and enforced by the existing operator gating; channel
  problems surface as non-blocking warnings.

## Completion vs quality vs safety

Implemented in `red-team/backend/lab_progress.py`:

- `OBJECTIVE_SPECS[module]["completion_groups"]` — list of OR-groups. A group is
  satisfied when **any** of its event types is observed *through the gated
  channel* (operator route `/op/...` + `backend=operator` + approved tool
  `attackbox`/`zap_repeater`/`zap_fuzzer` in lab mode). **All** groups must be
  satisfied → objective reached. One request can satisfy several groups.
- `OBJECTIVE_SPECS[module]["quality_tasks"]` — recommended methodology signals
  (matched by `event_types` and/or `via`) scored against **all** module events
  (any channel), so inspecting in the browser still earns methodology credit.
- Safety = the operator gate (`_event_counts_for_mode` / brute-force's dedicated
  logic) plus `warnings[]` when objective-shaped activity arrived outside the
  approved channel.

`compute()` now returns, in addition to the legacy fields:

```json
{
  "success": true,
  "objective": "Trigger a safe reflected XSS proof on /op/search.",
  "completion_score": 100,
  "quality_score": 40,
  "completed_required": ["XSS-shaped payload submitted", "Reflected input observed"],
  "completed_quality": [{ "id": "repeater_used", "label": "Test through Repeater" }],
  "missing_quality":   [{ "id": "marker_first", "label": "Test a harmless marker first",
                          "recommendation": "Test a benign marker before a live payload." }],
  "warnings": [],
  "next_recommended_action": "Test a benign marker (e.g. ATTENSE_XSS_PROOF) before a live payload."
}
```

Mission `success` == objective reached. Quality is reported, not required.

## Module-by-module completion events

Completion is gated (operator route + `backend=operator` + approved tool in lab
mode). Groups are ANDed; each bracket is an OR-group.

| Module | Objective | Completion groups |
|---|---|---|
| Recon | Discover & verify a hidden local route | `[hidden_clue_accessed OR recon_sequence_observed]` |
| XSS | Safe reflected XSS proof on `/op/search` | `[xss_payload_observed]` AND `[reflected_input_detected OR stored_payload_observed]` |
| Command Injection | Prove OS command execution on `/op/system/ping` | `[command_injection_detected]` |
| Path Traversal | Disclose a sensitive lab file via `/op/files/read` | `[sensitive_file_disclosed OR lab_file_disclosed]` AND `[traversal_pattern_observed]` |
| File Upload | Get a dangerous file accepted by `/op/files/upload` | `[unrestricted_upload_detected OR dangerous_extension_accepted OR uploaded_file_retrieved]` |
| CSRF | Change the profile via `/op/profile/update` without a token | `[profile_changed_without_csrf]` |
| Brute Force | Trip detector + confirm a credential on `/op/auth/login` | **stricter, unchanged:** 6+ `login_failed` + `credential_found`/`login_success` |

The target-lab operator routes emit all completion events for one correct action
(e.g. `?path=/etc/passwd` fires both `traversal_pattern_observed` and
`sensitive_file_disclosed`; one bypass upload fires both
`dangerous_extension_accepted` and `unrestricted_upload_detected`).

## Module-by-module quality events (advisory)

Scored for the report; never block completion. Common signals: request captured
in ZAP (`via` browser/repeater/fuzzer), Repeater used (`via=zap_repeater`),
Fuzzer used (`via=zap_fuzzer`), plus module-specific methodology:

- **Recon:** map portal home, check discovery files, verify a route with Repeater/AttackBox.
- **XSS:** capture request, inspect context, Repeater, marker-first, Fuzzer.
- **Command Injection:** capture, baseline first, Repeater, separator tested, Fuzzer.
- **Path Traversal:** capture, baseline first, Repeater, encoded variant.
- **File Upload:** multipart captured, inspect filename/Content-Type, Repeater, retrieve proof.
- **CSRF:** capture state-changing request, identify missing token, Repeater, local lure.
- **Brute Force:** capture, Repeater, Fuzzer, confirm credential.

Some quality signals (e.g. "context identified", "marker first") have no server
event yet; they remain as coaching recommendations, so a 100% quality score is a
stretch goal — there is always methodology to improve.

## How reports evaluate skipped steps

`red-team/backend/report_agent.py` now builds coaching from the objective model
when it is present:

- **What you did right:** objective reached (and the evidence that completed it),
  each observed methodology signal, and a safety-boundary confirmation.
- **What you missed:** every skipped methodology step is listed *as advisory*
  ("did not block completion") with an actionable `how_to_fix`; channel warnings
  appear as safety notes.
- **Summary / header:** shows completion % and methodology quality %.

Example (XSS, payload+reflection via Repeater, no marker/context first):
"Objective reached: reflected XSS proof was observed on `/op/search`. The student
identified a vulnerable input. Methodology to improve: test a benign marker and
inspect the reflection context before firing a payload."

## Early success handling

When the objective is reached but methodology is incomplete, the Workspace shows:
"Attack objective reached. You can view the report now, or keep improving your
methodology score (currently N%)." Students can finish immediately while still
being nudged toward better tradecraft.

## Safety (unchanged, still strict)

- Correct `/op/...` route + `backend=operator` required for operator completion.
- Only `attackbox`/`zap_repeater`/`zap_fuzzer` count; browser-only and
  `via=unknown` are visible but never complete (a warning is raised when the
  objective was reached only in the browser).
- target-agent-only; external targets blocked; AttackBox validator unchanged.
- No module is forced to use every tool — XSS/Cmd/Traversal can complete through
  Repeater alone; CSRF uses the local lure; Recon completes on verified route
  discovery; Brute Force keeps its stricter multi-signal logic.

## How this improves instructor demos

- A single correct exploit completes the lab — no scripted click-through.
- The report still teaches: it names exactly which methodology the student
  skipped and how to improve, turning a quick win into a Purple-Team lesson.
- Completion and quality are shown as separate scores, so an instructor can point
  at "objective reached, methodology 40%" and run the improvement conversation.

## Tests

`red-team/backend/tests/test_objective_progress.py` (plus the updated
`test_operator_gating.py`) cover: completion events alone mark success; missing
quality lowers quality_score without blocking; browser-only / `via=unknown` /
guided-surface objective evidence do not complete Operator Mode; the API exposes
completion/quality/missing_quality/next_recommended_action; brute force keeps its
stricter completion; and the report explains objective + skipped methodology.

---

## Completion pass — final implemented shape

The implementation was completed to expose the full contract and diagnostics.

### Final `compute()` API shape

Objective model + operator-gate diagnostics (in addition to legacy `tasks`,
`evidence`, `score`, `progress_percent`, `brute_force_activity`):

```json
{
  "success": true,
  "objective": "Trigger a safe reflected XSS proof on /op/search.",
  "completion_score": 100,
  "quality_score": 40,
  "completed_required": ["XSS-shaped payload submitted", "Reflected input observed"],
  "completed_quality": [{ "id": "repeater_used", "label": "Test through Repeater" }],
  "missing_quality":   [{ "id": "marker_first", "label": "Test a harmless marker first",
                          "recommendation": "..." }],
  "warnings": [],
  "next_recommended_action": "...",
  "tasks": [{ "id": "...", "label": "...", "done": false, "type": "optional", "reason": "..." }],
  "objective_tasks": [{ "id": "objective", "label": "...", "done": true, "type": "required" },
                      { "id": "repeater_used", "label": "...", "done": true, "type": "quality" }],
  "raw_event_count": 3,
  "counted_event_count": 2,
  "ignored_event_count": 1,
  "ignored_reasons": { "ignored_wrong_path": 0, "ignored_wrong_backend": 1,
                       "ignored_wrong_via": 0, "ignored_wrong_module": 0,
                       "ignored_variant_mismatch": 0, "ignored_unknown_reason": 0 },
  "last_observed_events": [{ "event_type": "...", "path": "...", "backend": "operator", "via": "...", "ts": 0 }],
  "last_counted_events":  [ ... ]
}
```

`OBJECTIVE_SPECS[module]` also exposes the explicit operator-contract metadata:
`objective`, `required_completion`, `quality_events`, `expected_operator_paths`,
`expected_backend` (`operator`), `allowed_operator_via`, `next_recommended_action`.
`completion_event_types(module_id)` returns one representative event per
completion group (the minimum objective evidence).

### Typed tasks (backward compatible)

`tasks` keeps its legacy fields (`title`, `complete`, `what`, `how`, `look_for`)
and gains `id`, `label`, `done`, `type` (`required` | `quality` | `optional`),
and `reason`. `objective_tasks` is the compact typed view: one `required`
objective task (which decides `success`) plus the `quality` tasks (which feed
`quality_score`).

### CSRF browser exception (the one documented exception)

CSRF's objective is genuinely browser-driven: the local lure at
`/op/evil/csrf-demo` auto-submits the state-changing request from the ZAP-routed
lab browser (`via=browser`). For CSRF **only**, `via=browser` is an approved
completion channel — but still tightly gated: the request must hit an `/op/`
route with `backend=operator`, and the completion event (`profile_changed_without_csrf`)
must fire. AttackBox curl (`via=attackbox`) also completes CSRF. The exception is
implemented via `BROWSER_COMPLETABLE_MODULES = {"csrf"}` / `_allowed_via_for()`
and does **not** generalize to any other module (proved by
`test_browser_exception_does_not_leak_to_other_modules`). `via=unknown` never
completes, even for CSRF.

### Operator-gate diagnostics

Every observed-but-uncounted in-scope event is classified into one of
`ignored_wrong_path`, `ignored_wrong_backend`, `ignored_wrong_via`,
`ignored_wrong_module`, `ignored_variant_mismatch`, `ignored_unknown_reason`.
The report renders these as an "Ignored evidence (operator gate)" coaching line
so students see exactly why browser/guided/unknown traffic did not count.

### Command safety scrub

All variant `ideal_commands` were rewritten to be AttackBox-validator-safe: no
shell pipes, `grep`, `&&`, `||`, `;`, redirection, loops, command substitution
`$()`, or backticks; no leaked credentials; and pointed at `/op/` routes.
Payloads that need special characters (XSS/command-injection/traversal) are now
described as ZAP Repeater/Fuzzer actions in comments, not as runnable AttackBox
commands. A test-time check runs every runnable line through
`operator_api.validate_command` — all pass.

### Tests run (final)

Full backend suite: **132 passed**. Added/updated: CSRF browser-exception tests,
the leak-guard test, the full API-shape test (all modules + brute_force), the
ignored-diagnostics classification test, and the report-explains-methodology
test. `test_student_safety.py` continues to assert `via=unknown` does **not**
complete Operator Mode.

### Final verdict

**GREEN (code)** — objective-based completion, quality scoring, operator-gate
diagnostics, the documented CSRF exception, and the command scrub are all
implemented and covered by passing unit tests, with compileall, frontend build,
and `docker compose config` green. **AMBER (runtime)** only for the manual Docker
smoke tests and the pending target-lab redeploy, which are environment steps.
