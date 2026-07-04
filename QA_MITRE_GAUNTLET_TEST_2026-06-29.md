# ATTENSE — Full Module & Gauntlet QA Test Report

**Date:** 2026-06-29
**Tester role:** Senior Cyber-Security PM / Software Tester
**Scope:** All 7 attack modules (per MITRE ATT&CK), all 3 Gauntlet chains, API & infra.
**Method:** Real end-to-end attacks driven from the AttackBox container (`via="attackbox"`,
i.e. the genuine operator/lab path) against `target-agent`, scored through the red-team
backend API (`/api/sessions/*/check-progress`, `/api/chain-sessions/*`).

---

## 1. Environment / Infra — PASS

All 14 containers `Up (healthy)`. Reachability from AttackBox verified:

| Target | Result |
|---|---|
| red-team backend `http://attense_red_team_backend:8000/health` | 200 |
| target-agent `http://target-agent/` | 200 |
| signal-store `http://signal-store:8000/health` | 200 |

`GET /api/modules` returns all 7 modules, each with a full MITRE ATT&CK block
(tactics + techniques). No missing metadata.

---

## 2. Attack Modules — 7/7 PASS

Each module: create session (lab mode) → start → run real attack vs target-agent →
`check-progress`. `success=True` means the module's required success-marker events fired.

| Module | MITRE techniques | Result | Notes |
|---|---|---|---|
| **recon** | T1595.002, T1595.003, T1592.002 | ✅ PASS | `recon_sequence_observed` fires after 4 distinct areas. |
| **brute_force** | T1589.001, T1110.001, T1110.004 | ✅ PASS | `brute_force_pattern` + `credential_found` (admin/password123). |
| **xss** | T1595.002, T1059.007, T1189 | ✅ PASS | `xss_payload_observed` + `reflected_input_detected`. |
| **cmd_injection** | T1190, T1059.004, T1033 | ✅ PASS | `command_injection_detected` (`; id`, `&& whoami`). |
| **dir_traversal** | T1190, T1083, T1552.001 | ✅ PASS | `sensitive_file_disclosed` (`../../etc/passwd`). |
| **file_upload** | T1190, T1505.003 | ✅ PASS | `unrestricted_upload_detected` (.php / .sh accepted). |
| **csrf** | T1204.001, T1565.001, T1078 | ✅ PASS | `profile_changed_without_csrf` (no token, email mutated). |

**Verdict:** All modules detect and score the intended attack correctly, with accurate
MITRE mapping. No application defects found.

---

## 3. Gauntlet Chains — 3/3 PASS

Each chain: start → for every step run its attack → `check` → `advance` (which resets
target evidence) → final `report`.

| Chain | Steps | Grade | Avg | Completed |
|---|---|---|---|---|
| **full_compromise** | recon → brute_force → xss → csrf | A | 100% | ✅ |
| **root_the_box** | recon → cmd_injection → dir_traversal → file_upload | A | 100% | ✅ |
| **data_exfiltration** | recon → brute_force → dir_traversal → csrf | A | 100% | ✅ |

Every step scored 100% and `passed=True`; per-phase snapshots persist correctly into
the final report after evidence reset.

**Negative gating test (important):** Starting `root_the_box` and calling `advance`
*without* performing the step returned **HTTP 409** —
`"Current step 'Recon' is not yet complete. Score must reach 60%."`
The step gate is enforced, not a no-op.

---

## 4. Defects Found

**Application defects: NONE.** The platform behaved correctly in every scenario.

### Test-harness / behavioral notes (not app bugs)
1. **GET vs POST (tester error, fixed):** `curl --data-urlencode` without `-G` forces a
   POST; the GET-based endpoints (`/search`, `/system/ping`, `/files/read`) silently no-op.
   Using `curl -G` resolved it. Worth noting for anyone scripting the AttackBox.
2. **Synthetic-event cooldown (by design):** `brute_force_pattern` de-dupes within 20s and
   `recon_sequence_observed` fires once per IP until evidence is reset. Rapid back-to-back
   runs from the same IP can suppress these. `check-progress` scopes by `since=`, and chain
   `advance` resets evidence, so real single-learner flows are unaffected.
3. **CSRF state persistence:** the profile email persists in target-agent memory; re-sending
   the same email yields no change event. Use a fresh value per attempt (the lab reset does
   not clear `_PROFILES`).

---

## 4b. Mutation Mode — ❌ FAIL (target-agent not wired)

Mutation Mode is meant to rewrite the target mid-mission so the learner must adapt
their technique (same MITRE family, new delivery). **It does not work end-to-end.**

### Evidence
| Test | Result |
|---|---|
| `POST target-agent /lab/mutations/activate` | **HTTP 404** (endpoint does not exist) |
| `POST /api/sessions/{sid}/mutations/trigger` (UI path) | **HTTP 404 "NOT FOUND"** |
| `POST /api/sessions/{sid}/mutations/schedule` then fire | status → **error: `404: NOT FOUND`** (after ~8s Ollama timeout) |
| Activate `bf_endpoint_renamed`, then `/auth/signin` | 404 — login never moved; `/auth/login` still works |
| Activate `xss_script_filtered`, then `?q=<script>` | `<script>alert(1)</script>` reflected verbatim — not filtered |
| Activate `cmd_semicolon_filtered`, then `host=127.0.0.1; id` | still injects `uid=0` — not filtered |

### Root cause
`target-agent/app/mutation_engine.py` is fully implemented (catalog + `activate` /
`get_flat_active_for_request`) but is **dead code — never imported by `main.py` or any
route** in the live container. Two pieces are missing on the target side:
1. HTTP endpoints `/lab/mutations/activate` and `/lab/mutations/deactivate` in `main.py`.
2. Per-route enforcement — auth/search/system/files/profile routes never call
   `mutation_engine.get_flat_active_for_request()`, so behavior never changes.

The **red-team backend side is complete** (catalog, scheduler, intensity windows, taunts,
timeline, Ollama picker with rule-based fallback). The failure is isolated to the target.

### Intended mutations & MITRE mapping
Mutations are defensive controls; the *adapted* attack stays in the same ATT&CK technique:

| Mutation | Breaks | Adapted technique (MITRE) |
|---|---|---|
| `bf_json_required` | form login | T1110.001 Password Guessing (JSON body) |
| `bf_endpoint_renamed` | `/auth/login` | T1595.003 Wordlist Scanning → T1110.001 (re-find endpoint) |
| `xss_script_filtered` | `<script>` | T1059.007 JavaScript (event-handler `onerror`/`onload`) |
| `xss_param_renamed` | `?q=` | T1595.003 → T1059.007 (re-find reflected param) |
| `cmd_semicolon_filtered` | `;` | T1059.004 Unix Shell (`&&`, `\|`, `$()`) |
| `cmd_param_renamed` | `?host=` | T1059.004 (re-find injectable param `?target=`) |

(Backend catalog exposes these 6; the target's `FLAT_MUTATIONS` also defines
`dt_dotdot_filtered`, `fu_extension_blocklist`, `csrf_referer_check` — not yet exposed
through the backend trigger API.)

---

## 5. Conclusion

✅ **All 7 MITRE-mapped attack modules pass.**
✅ **All 3 Gauntlet chains complete with grade A, gating verified (positive + negative).**
✅ **Infra, API, and MITRE metadata fully healthy.**
❌ **Mutation Mode is non-functional** — target-agent is missing the `/lab/mutations/*`
   endpoints and per-route enforcement; `mutation_engine.py` is dead code. Backend side OK.

The core platform (modules + gauntlet) is solid. Mutation Mode needs the target-agent
wiring completed before it can be shipped.
