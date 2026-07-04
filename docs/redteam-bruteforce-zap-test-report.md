# ATTENSE Red Team Brute-Force + ZAP Pipeline Test Report

## 1. Branch and commit tested

- **Branch:** `feature/attacker-activity-log`
- **Base commit under test:** `e07fe63` — *Fix brute-force lab pipeline, ZAP proxy routing, and PortSwigger-style steps*
- **This report + added tests** are committed on top of that base on the same branch.

## 2. Test date/time

- **2026-07-04**, ~13:00 EDT. Host: Windows 11, Docker Desktop; running lab stack (red-team-frontend, red-team-backend, target-agent, zap, attackbox all healthy).

## 3. Scope

Verification-only pass over the full Operator/Guided brute-force authentication lab:
ZAP Workspace, Proxy History, Inspector, Repeater, Fuzzer, AttackBox, target-agent
evidence, progress scoring, and mission reporting. No new attack types, no loosened
safety controls, no credential exposure. Small test-only additions and one
test-precision fix only.

## 4. Architecture summary

```
Operator browser traffic:
  Red Team UI  ──/target-zap/…──▶  frontend nginx  ──rewrite──▶  backend /zap-browse/{path}
       └▶ requests(proxies=zap:8080)  ──▶  OWASP ZAP  ──▶  target-agent /op/…  ──▶ ZAP Proxy History

Repeater / Fuzzer:  frontend ──/api/operator/zap/{repeater,fuzzer}/send──▶ backend
       └▶ ZAP sendRequest ──▶ target-agent /op/auth/login  (via = zap_repeater | zap_fuzzer)

Scoring (red-team/backend/lab_progress.py):
  Operator (lab mode) brute-force completes ONLY when, on /op/auth/login with
  backend=operator and via ∈ {attackbox, zap_repeater, zap_fuzzer}:
    ≥ 6 failed logins  AND  credential_found | login_success.
  Browser traffic appears in history (source=browser) but never completes.
```

- ZAP is a standalone desktop-style window: `routes/ZapWorkspace.jsx` opened via
  `window.open('/zap-workspace?session_id&module_id&mode')` from `ZapLauncher`.
- Reusable components in `components/zap/` (`useZapController`, `ZapHistory`,
  `ZapInspector`, `ZapRepeater`, `ZapFuzzer`, `ZapLauncher`, `zapUtils`).

## 5. Automated tests added/updated

All under `red-team/backend/tests/` (run with `pytest red-team/backend/tests -q`).

| File | Tests | Covers |
| --- | --- | --- |
| `test_student_safety.py` (updated) | +`test_operator_completes_via_each_approved_tool` (parametrized attackbox/zap_repeater/zap_fuzzer), +`test_operator_login_success_also_completes` | Item B: each approved tool completes; login_success path |
| `test_target_evidence.py` (new) | `test_detect_via_classification` (7 params), 3× `brute_force_pattern` metadata tests | Item C (detect_via), Item D (pattern inherits path/method/via/backend) |
| `test_frontend_wiring.py` (new) | 8 static-source checks | Frontend A–J: vite order, nginx route, /zap-workspace route, launcher context, api context+headers, controller sends, history actions, § marker, operator/guided hint separation + no credential leak |
| existing | auto-guard, validate_command allow/block, ZAP normalization, browse local-only, history model + truncation, gating negatives | Items A, B (neg), E, F, G |

**Result: 30 passed** (`pytest red-team/backend/tests -q` → `30 passed in ~30s`).

## 6. Build/config checks

| Check | Command | Result |
| --- | --- | --- |
| Python compile | `python -m compileall red-team apps/target-lab apps/signal-mapper apps/control-api blueteam` | **PASS** (adapted: repo moved `target-agent`→`apps/target-lab`, `signal-store`→`apps/signal-mapper`, `attense-app`→`apps/control-api`) |
| Backend tests | `pytest red-team/backend/tests -q` | **PASS** — 30 passed |
| Frontend build | `cd red-team/frontend && npm run build` | **PASS** — built in ~6s (chunk-size advisory only) |
| Compose validate | `docker compose config` | **VALID** |

## 7. Runtime tests (Docker)

Stack already running and healthy; a targeted rebuild/recreate of `red-team-frontend`
was performed via `docker compose build` + `up -d` in the prior sprint (image builds
clean). A full `docker compose down && up --build` of the entire SIEM stack
(Wazuh/TheHive/Cortex/Cassandra/Elasticsearch) was **not** run here — see §14.

| Container | State |
| --- | --- |
| attense_red_team_frontend | Up, healthy |
| attense_red_team_backend | Up, healthy |
| attense_target_agent | Up, healthy |
| attense_zap | Up, healthy |
| attense-attackbox | Up, healthy |

## 8. Manual/HTTP tests

Driven with `curl` against `http://localhost:3000` (the exact flows the UI triggers).

- **A** UI: `GET /` → 200, `<title>ATTENSE — Red Team Console</title>`.
- **B** `/target-zap/auth/login` → 200, target Sign-In form (`action=/target-zap/auth/login`), **no** React `id="root"`.
- **C** browser POST wrong creds → 401, recorded in ZAP history as `source=browser`.
- **D** `/zap-workspace?...` → 200 (SPA route serves; connection bar reads session/module/mode from query).
- **E/F** Inspector/Repeater fields: history `zap_repeater` row has all 13 model fields, `session_id`+`module_id` linked, `source=zap_repeater`.
- **E** Fuzzer + local wordlist → operator mission completes (`success=True`, 18 fails, credential via `zap_fuzzer`).
- **F** browser-only 8 wrong logins → mission `success=False`, lab-counted attempts `0`.
- **H** safety: external blocked, local allowed (details in §10).

## 9. PortSwigger alignment check

- **Guided Mode** (`/auth/login`): username enumeration via distinct error messages
  ("Incorrect password for X" vs "Account not found"), planted `admin:password123`,
  success by 302→/profile. Guided hints (beginner tip + enumeration `watchFor`) intact.
- **Operator Mode** (`/op/auth/login`): generic "Invalid credentials", no enumeration,
  evidence-based completion via ZAP Repeater/Fuzzer/AttackBox. Operator hints are a
  separate staged set (capture → Repeater → § marker → compare status/length/redirect →
  local wordlist) that **never reveal the credential**. Verified by
  `test_operator_hints_separate_and_no_credential_leak`.

## 10. Safety / local-only validation

| Vector | Result |
| --- | --- |
| Repeater → `http://example.com`, `https://google.com`, `http://8.8.8.8` | **blocked** |
| Repeater → `/op/auth/login`, `/auth/login` | **allowed** |
| AttackBox → `curl -I http://target-agent` | **allowed (ok)** |
| AttackBox → `curl http://example.com`, `nmap google.com`, `nmap 8.8.8.8`, `ping google.com`, `nc google.com 80` | **blocked** |
| AttackBox → `python3 -c` external, `bash -lc` external | **blocked** (unit test) |
| `browse_through_zap` path mapping — `http://…`, `http:/…` smuggled scheme | **blocked (400)**; upstream host hard-coded `target-agent` |
| Malformed `http://target-agent/http://target-agent/…` | **blocked** by `normalize_zap_target_path` |
| Operator credentials in frontend source | **none** (`git grep` clean; seed only in gitignored `secrets/` + AttackBox `/lab/operator-passwords.txt`) |

## 11. Results table

| Area | Test | Expected | Actual | Status | Evidence/Notes |
| ---- | ---- | -------- | ------ | ------ | -------------- |
| Build | compileall (5 trees) | no errors | COMPILE OK | PASS | apps/* paths adapted |
| Build | pytest backend | all pass | 30 passed | PASS | §5 |
| Build | npm run build | success | built ~6s | PASS | chunk-size advisory only |
| Build | docker compose config | valid | VALID | PASS | |
| Auto A | ENABLE_AUTO_ATTACKS guard | false blocks | false→blocked, true→allowed | PASS | `test_auto_attacks_disabled_by_default` |
| Auto B | /auth/login not complete Operator | success False | False | PASS | gating test |
| Auto B | /op via browser/unknown/empty/missing | success False | False (all) | PASS | gating test |
| Auto B | /op via attackbox/zap_repeater/zap_fuzzer | success True | True (all 3) | PASS | new parametrized test |
| Auto B | < 6 failures | success False | False | PASS | gating test |
| Auto B | 6+ + credential/login_success | success True | True | PASS | new test |
| Auto C | detect_via ZAPRepeater/ZAPFuzzer/AttackBox/prefix/unknown | correct via | all correct | PASS | 7 params |
| Auto D | brute_force_pattern inherits path/method/via/backend | inherited | inherited (op + guided) | PASS | not hardcoded /auth/login |
| Auto E | ZAP normalize allow/block | as specified | allow local, block external | PASS | |
| Auto F | history model fields | 13 fields storable | all present | PASS | model + truncation |
| Auto G | AttackBox allow/block | as specified | correct | PASS | validate_command |
| FE A–J | wiring static checks | present/ordered | all present | PASS | `test_frontend_wiring.py` |
| Run A | UI at :3000 | Red Team UI | 200 + title | PASS | |
| Run B | /target-zap login | target form, not index | 200, form, no id=root | PASS | |
| Run C | browser POST | 401 + source=browser, no complete | 401, recorded | PASS | |
| Run D | /zap-workspace | SPA route serves | 200 | PASS | reads query context |
| Run E | Inspector fields (repeater row) | full req/resp visible | 13 fields present | PASS | session/module linked |
| Run F | Send to Repeater | via=zap_repeater, session-linked | confirmed | PASS | |
| Run G | Fuzzer completes mission | 6+ fails + cred via zap_fuzzer | success True, 18 fails | PASS | wordlist found Br3akMe!2025 |
| Run H | browser-only negative | success False | False, 0 counted | PASS | |
| Run I | Guided PortSwigger | enumeration + hints intact | intact, separate hints | PASS | code + §9 |
| Run J | safety blocked/allowed | external blocked, local ok | as expected | PASS | §10 |
| UI | visual click-through (open window, buttons, § render) | works | not driven | NOT RUN | no browser automation here |
| Run | full `compose down && up --build` | stack healthy | targeted rebuild only | PARTIAL | SIEM stack not cold-booted |

## 12. Issues found

- **One test-precision bug in the new suite** (not a pipeline bug): the initial
  `test_vite_target_zap_before_target` matched the substring `'/target'` inside an
  explanatory comment rather than the proxy key, producing a false FAIL. The vite
  proxy keys are correctly ordered.
- **No pipeline defects found.** All infra/scoring/safety behavior matched the spec.

## 13. Fixes applied

- Tightened `test_vite_target_zap_before_target` to match the proxy **key**
  definitions (`'/target-zap':` / `'/target':`), not comment text. Re-ran → PASS.
- No production/source fixes were needed this pass.

## 14. Remaining risks

- **Visual UI not automated:** the literal `window.open`, the row Inspect/Repeater/
  Fuzzer button clicks, and the on-screen § insertion were verified only at the
  HTTP/API and static-source level. A 5-minute manual click-through is recommended
  before a live demo.
- **Full stack cold boot not exercised here:** `docker compose down && up --build`
  of the entire SIEM stack (~10 min to healthy) was not run to avoid disrupting the
  live stack; the frontend image was rebuilt via compose and recreated (healthy).
  Recommend one clean cold boot before the defense.
- **Browser history session linkage:** browser-through-ZAP rows carry
  `session_id=None` by design (iframe navigations can't attach a session). They
  still appear in history and never count toward completion — acceptable, but the
  ZAP Workspace shows all local history rather than session-filtered browser rows.

## 15. Final verdict

**GREEN — demo-ready.**

The Operator brute-force pipeline is proven end-to-end: browser traffic flows through
ZAP into Proxy History but cannot complete the mission; ZAP Fuzzer/Repeater/AttackBox
against `/op/auth/login` complete it under the strict evidence gate (path + backend +
approved via + ≥6 failures + credential); external targets are blocked; and operator
credentials are never exposed in the frontend. 30 automated tests pass and all runtime
HTTP checks pass. The only untested surfaces are purely visual UI interactions and a
full-stack cold boot — neither is a pipeline blocker. Do a short manual click-through
and one clean `docker compose up --build` before the live demo.
