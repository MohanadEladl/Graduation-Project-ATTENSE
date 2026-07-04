# Red Team — PortSwigger-Style Flow Applied to All Modules

## 1. Branch and commit tested

- **Branch:** `feature/attacker-activity-log`
- **Base commit:** `e07fe63` (brute-force lab pipeline + ZAP proxy routing)
- **This change:** generalizes the brute-force operator/guided evidence contract
  to every remaining Red Team module and brings operator hints to parity.

## 2. Scope

The brute-force module already had the correct two-mode learning model:

- **Guided (tutorial) Mode** — beginner path, concept hints, easier validation.
- **Operator (lab) Mode** — tool-based practice; browser traffic is routed
  through `/target-zap` and shows in ZAP Proxy History, but only evidence from an
  approved local tool (`attackbox`, `zap_repeater`, `zap_fuzzer`) against the
  `/op/` operator surface (`backend=operator`) completes the mission.

That contract lived in a brute-force-only helper
(`_is_brute_force_event_for_mode`). Every **other** module (recon, xss,
cmd_injection, dir_traversal, file_upload, csrf) only checked the tool `via` in
lab mode — it did **not** require the `/op/` operator route or `backend=operator`,
and tutorial mode counted operator events too. This change closes that gap so all
seven modules share one evidence contract.

## 3. Module-by-module PortSwigger alignment

Each module maps to the PortSwigger Web Security Academy testing loop: capture
the request → inspect request/response → send to Repeater → modify one parameter
→ use the Fuzzer for payload iteration → compare an observable difference →
confirm the objective → record evidence → update progress → report.

| Module | Guided route | Operator route | Objective | Observable proof |
|---|---|---|---|---|
| Recon | `/`, `/robots.txt`, `/.well-known/security.txt` | `/op/`, `/op/.git/config` | Map attack surface, find hidden route | `recon_sequence_observed` after 4+ areas |
| XSS | `/search` | `/op/search` | Reflected input, identify context | `xss_payload_observed` + `reflected_input_detected` |
| Command Injection | `/system/ping` | `/op/system/ping` | Prove RCE with a harmless command | `command_injection_detected` |
| Path Traversal | `/files/read` | `/op/files/read` | Disclose a safe lab file via `../` | `sensitive_file_disclosed` |
| File Upload | `/files/upload` | `/op/files/upload` | Accept a dangerous extension/type | `unrestricted_upload_detected` |
| CSRF | `/profile/update`, `/evil/csrf-demo` | `/op/profile/update`, `/op/evil/csrf-demo` | State change without a token | `profile_changed_without_csrf` |
| Brute Force | `/auth/login` | `/op/auth/login` | 6+ failures + valid credential | `brute_force_pattern` + `credential_found` |

Per-module walkthroughs, variants (Easy/Medium/Hard), MITRE ATT&CK mappings, and
OWASP/CWE/CAPEC references already exist in `apps/red-team-api/backend/lab_progress.py`
(`MODULE_VARIANTS`, `WALKTHROUGH`, `SECTION_TECHNIQUES`, `DATABASE_REFERENCES`)
and are unchanged.

## 4. Guided vs Operator design

Implemented uniformly in `lab_progress._event_counts_for_mode()`:

- **Lab / Operator mode** — an event counts only when **all** hold:
  - `via ∈ {attackbox, zap_repeater, zap_fuzzer}`
  - `backend == "operator"`
  - `path` starts with `/op/` (derived events are exempt — see below)
  Browser-only (`via=browser`) and direct (`via=unknown`) traffic is visible in
  the evidence panel but never completes the mission.
- **Tutorial / Guided mode** — counts guided-surface evidence from any channel
  (`backend != "operator"`), so operator activity never cross-completes a guided
  mission and vice-versa.

`brute_force` keeps its dedicated `_is_brute_force_event_for_mode` +
`_brute_force_activity` (failed-attempt-count logic), which already encodes the
same contract for the exact `/op/auth/login` path — so the recent brute-force
fixes are untouched.

### Derived (synthetic) events

`brute_force_pattern` and `recon_sequence_observed` are minted by the
target-agent's pattern detector, not by a concrete `/op/` route, so they inherit
`via` + `backend` from the triggering request. They are gated on backend + tool
channel but exempt from the `/op/` path-prefix check. `brute_force_pattern`
already inherited `backend`; this change makes `recon_sequence_observed` inherit
`backend` too (`apps/target-lab/app/evidence.py`), so an operator recon sweep is
correctly recognized in lab mode.

## 5. Evidence events per module

Emitted by `apps/target-lab/app` routes (`routes/` guided, `routes_op/`
operator). Every operator route already records `path="/op/..."`,
`extra={"backend": "operator"}`, and `via=detect_via()`:

- **recon:** `portal_visited`, `route_discovered`, `hidden_clue_accessed`, `recon_sequence_observed`
- **xss:** `search_used`, `xss_payload_observed`, `reflected_input_detected`
- **cmd_injection:** `diagnostics_used`, `command_separator_observed`, `command_injection_detected`
- **dir_traversal:** `file_viewer_used`, `traversal_pattern_observed`, `sensitive_file_disclosed`
- **file_upload:** `file_upload_used`, `file_saved`, `dangerous_extension_accepted`, `unrestricted_upload_detected`
- **csrf:** `profile_update_used`, `csrf_token_missing`, `csrf_lure_visited`, `csrf_lure_submitted`, `profile_changed_without_csrf`
- **brute_force:** `login_failed`, `login_success`, `brute_force_pattern`, `credential_found`

Each event carries `event_type`, `ts`, `module_id`, `path`, `method`,
`severity`, `source_ip`, `via`, `learner_message`, and `extra` (with `backend`).
Response bodies are truncated in ZAP history (`MAX_HISTORY_BODY_LEN`).

## 6. Progress criteria per module

Success = every entry in the active variant's `success_event_types` is observed
**through the gated channel** for the current mode. Defaults (first variant):

- recon → `recon_sequence_observed`
- xss → `xss_payload_observed` + `reflected_input_detected`
- cmd_injection → `command_injection_detected`
- dir_traversal → `sensitive_file_disclosed`
- file_upload → `unrestricted_upload_detected`
- csrf → `profile_changed_without_csrf`
- brute_force → 6+ `login_failed` + `credential_found` (count-based)

## 7. ZAP / AttackBox usage per module

The ZAP Workspace (Proxy History, Inspector, Repeater, Fuzzer) is module-agnostic
and shared by all modules: the launcher passes `session_id`, `module_id`, and
`mode`; Repeater/Fuzzer forward that context and their evidence appears in
progress and reports. Recommended tools per module are declared in
`LAB_REQUIRED_TOOLS` (`missionBriefings.js`). All ZAP/AttackBox traffic remains
target-agent-only (`normalize_zap_target_path`, `validate_command`).

## 8. Safety rules (unchanged, verified by tests)

- External targets blocked across ZAP and AttackBox (`google.com`, `example.com`,
  `8.8.8.8`, arbitrary URLs, external IPs, `bash -lc "curl ..."` wrappers).
- ZAP target normalization is local-only; smuggled schemes refused without
  touching the network.
- Operator hints never reveal a credential or working solution and steer toward
  approved local tools only (enforced for all 7 modules by a new test).
- Payloads remain local, harmless, and educational; no external callbacks, no
  real web shells, no destructive commands.

## 9. Mission Step / Validator Consistency Pass

This pass aligns the student-facing mission steps with the strict AttackBox
validator in `apps/red-team-api/backend/operator_api.py`; the validator itself remains
unchanged.

- Rewritten modules: `recon`, `xss`, `cmd_injection`, `dir_traversal`,
  `file_upload`, and `csrf`; `brute_force` was only tagged for consistency.
- Every lab step now declares an explicit expected tool (`Browser`,
  `ZAP Proxy History`, `ZAP Inspector`, `ZAP Repeater`, `ZAP Fuzzer`,
  `AttackBox`, or `Report`).
- Only `tool: "AttackBox"` steps carry copy-paste `command` / `commands`
  values, and those commands are local `target-agent` requests that pass
  `validate_command()`.
- XSS payloads, command-injection separator/substitution payloads, path
  traversal variants, upload multipart edits, and CSRF lure testing were moved
  into ZAP Repeater/Fuzzer or Browser instructions instead of AttackBox command
  blocks.
- Output-filtering examples no longer use `| grep` or shell pipelines; students
  are told to compare full output, status, response length, and response bodies
  in ZAP.
- Backend progress copy was refreshed to match the same Operator Mode tool
  contract without changing the evidence gates.
- Automated coverage now imports `missionBriefings.js`, walks all lab steps, and
  runs every AttackBox-tagged command through `validate_command()`. It also
  asserts that ZAP payload instructions may contain shell syntax precisely
  because they are not AttackBox shell commands.

Runtime smoke performed:

- `docker compose down` and `docker compose up --build -d` completed
  successfully.
- All compose services reached healthy/running status, including `target-agent`,
  `zap`, `attackbox`, `red-team-backend`, and `red-team-frontend`.
- Running-stack Operator API smoke passed for `recon`, `xss`, `cmd_injection`,
  `dir_traversal`, `file_upload`, and `csrf` using real lab sessions and local
  ZAP Repeater requests through the frontend proxy.

Remaining manual tests needed:

- Visual click-through in the browser UI for each module's new step labels and
  hints.
- CSRF local lure submission from the actual Operator browser, not only the
  Repeater/API equivalent.

## 10. Tests run

- `pytest apps/red-team-api/backend/tests -q` → **89 passed**.
  - New: `test_operator_gating.py` — per-module (recon/xss/cmd/traversal/upload/csrf):
    approved tools complete; browser-only does not; `via=unknown` does not;
    guided surface does not complete operator; tutorial completes on guided
    browser evidence; operator events do not cross-complete tutorial; browser
    operator cards are visible but `counts=False`.
  - Extended: `test_frontend_wiring.py` — all 7 modules have safe, tool-oriented
    operator hints with no solution leak.
  - Extended: `test_student_safety.py` imports `missionBriefings.js` and
    validates every AttackBox-tagged `command` / `commands` value with
    `validate_command()`.
  - Unchanged and still green: brute-force operator gating, target-evidence
    synth-metadata inheritance, ZAP/AttackBox safety.
- `python -m compileall apps/red-team-api/backend apps/target-lab/app` → OK.
- `node --check` on `missionBriefings.js` → OK.
- `npm install` (red-team frontend) → up to date.
- `npm run build` (red-team frontend) → built in ~6 s.
- `docker compose config` → valid.
- `docker compose down` → OK.
- `docker compose up --build -d` → OK.
- Running-stack Operator API smoke for recon/xss/cmdi/traversal/upload/csrf → OK.

## 11. Remaining risks

- **Visual UI smoke:** the running-stack smoke used real sessions and ZAP
  Repeater API requests through the frontend proxy, but did not click through the
  browser UI manually.
- **CSRF browser lure:** the local lure flow was verified through the same local
  Repeater/request path; the actual Operator browser button click still needs a
  visual pass.
- Frontend bundle is large (chunk-size warning only), no functional impact.

## 12. Final verdict

**GREEN (code and API smoke)** - the shared operator/guided evidence contract
and the mission-step/validator consistency pass are covered by automated tests,
frontend build, compose validation, compose rebuild, and running-stack Operator
API smoke. **AMBER (visual UI)** only for the remaining manual browser
click-through checks.
