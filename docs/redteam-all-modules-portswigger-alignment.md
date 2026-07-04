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
OWASP/CWE/CAPEC references already exist in `red-team/backend/lab_progress.py`
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

## 9. Tests run

- `pytest red-team/backend/tests -q` → **85 passed**.
  - New: `test_operator_gating.py` — per-module (recon/xss/cmd/traversal/upload/csrf):
    approved tools complete; browser-only does not; `via=unknown` does not;
    guided surface does not complete operator; tutorial completes on guided
    browser evidence; operator events do not cross-complete tutorial; browser
    operator cards are visible but `counts=False`.
  - Extended: `test_frontend_wiring.py` — all 7 modules have safe, tool-oriented
    operator hints with no solution leak.
  - Unchanged and still green: brute-force operator gating, target-evidence
    synth-metadata inheritance, ZAP/AttackBox safety.
- `python -m compileall red-team/backend apps/target-lab/app` → OK.
- `node --check` on `missionBriefings.js` → OK.
- `npm run build` (red-team frontend) → built in ~10 s.
- `docker compose config` → valid.

## 10. Remaining risks

- **Runtime deploy of target-agent:** the `evidence.py` change (recon synth
  backend inheritance) requires the target-agent container to be rebuilt /
  redeployed (`docker cp` + restart, or `docker compose up --build`) before it
  takes effect at runtime. Guided recon is unaffected; only operator-mode recon
  completion depends on it.
- **Full end-to-end manual validation** (the A–G browser walkthroughs) was not
  executed in this session — it requires bringing the whole Docker stack up.
  Logic is covered by unit tests against the real gating + real target evidence
  shapes.
- Frontend bundle is large (chunk-size warning only), no functional impact.

## 11. Final verdict

**GREEN (code)** — the brute-force operator/guided contract is now applied
uniformly to all seven modules, proven by unit tests against the real evidence
shapes, with backend + target-agent + frontend + tests + build + compose all
passing. **AMBER (runtime)** only pending a target-agent redeploy and the manual
Docker walkthrough, which are environment steps outside this change.
