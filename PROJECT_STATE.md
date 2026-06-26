# PROJECT_STATE.md
<!-- Updated after each meaningful action. This is current state, not a changelog. -->

## 1. Current focus
Live scoring path fully wired end to end. `run_bridge()` now routes live incidents (`scenario_id="APP-0X"`, no scenario suffix) through `compute_live_thresholds()` + real event-metadata severity to build a synthetic scenario dict, which feeds `score_incident()` unchanged. Severity vocabulary normalisation (`"critical"` → `"very_high"`) is required for R09 to work correctly on live data; missing severity fails loud with `ValueError` — no silent default.

## 2. Recently completed
- **`bridge.py` integration** — `run_bridge()` now calls `score_incident()` after `generate_report()` and merges the `ScoringResult` into the report dict. `outcome` (uppercase, timestamp-based) and `verdict` (lowercase, score-based) coexist under distinct keys and are never conflated. Full 9-rule breakdown (`scoring_rules`) included for the Gemini layer. `_load_rule_data()` raises `ValueError` on unknown or missing rule files.
- **Synthetic integration test** — `attense-app/test_bridge_merged_dict.py`; builds real XSS-S1 Incident from fixture, calls full bridge pipeline, verifies merged dict structure and all assertions.
- **`scoring_engine.py` implemented** — `attense-app/pipeline/scoring_engine.py`; evaluates R01–R09 with three statuses (triggered/passed/not_applicable), computes penalty, ttc_factor, difficulty bonus, final score, and verdict.
- **Cross-file validation** — engine run against one scenario from each of APP-02 through APP-06 (CMDI-S2, DIR-S3, FUP-S2, CSRF-S2, BA-S1); all 5 match expected_evaluation exactly.
- **29 unit tests passing** — `attense-app/test_scoring_engine.py`; covers all 9 rule statuses per scenario including R09 severity gate (not_applicable at severity=low) and R03/R06/R07/R08 not_applicable chain in S2.
- **Manual trace verified** — all three XSS scenarios (XSS-S1, XSS-S2, XSS-S3) traced by hand against rules R01–R09; all match `expected_evaluation` exactly.
- **5 new event types added end-to-end** — `evidence_preserved`, `eradication_completed`, `recovery_validated`, `lessons_learned_recorded`, `dismissal_approved` wired through: `allowed_events.py`, `constants.py`, `watcher/agent.py`, `bridge.py`, `core/blueactions/post_incident_actions.py`, `hive_event_translator.py`, `webhook_router.py` (self-approval guard on `dismissal_approved`), `analyst_action_extractor.py`, and the `AnalystEventType` Pydantic enum.
- **Keyword deduplication** — dismissal/lessons-learned regex centralized in `hive_keywords.py`; imported by both translator and extractor.
- **Evaluation pipeline scaffolded** — bridge, Gemini report generator, orchestrator added (commit a55148e).
- **`live_thresholds.py` created** — `attense-app/ATTENSE_app/AI/live_thresholds.py`; `CANONICAL_SCENARIOS` dict (all 6 attack types, `cvss_base_score` + `detection_difficulty` each verified against the S1 scenario block in the corresponding JSON file); `compute_live_thresholds(scenario_id)` returns `{cvss_base_score, detection_difficulty, ttc_expected_sec, ttc_max_sec, mtta_threshold_sec}` using `max(900, round(3600*(10−cvss), 2))` formula. Cross-checked against 4 fixture `computed_thresholds` blocks (APP-01/02/03/04); all match.
- **Live scoring path wired in `bridge.py`** — `_ATTACK_RULE_FILES` rekeyed to `"APP-01"…"APP-06"`; `_load_rule_data()` simplified to direct lookup; `_SEVERITY_NORMALIZE` + `_extract_alert_severity()` added (reads `alert_raised` event `metadata["severity"]`, normalises `"critical"` → `"very_high"`, raises on missing severity); `run_bridge()` detects when `scenario_id` has no matching scenario block and builds a synthetic one from `compute_live_thresholds()` + real event severity, then passes it to `score_incident()` unchanged. Verified end-to-end with `attense-app/test_live_scoring.py`.
- **Gemini SDK migrated to `google-genai`** — `report_generator.py`'s `_call_gemini()` migrated from the deprecated `vertexai.generative_models.GenerativeModel` to `google-genai` 2.9.0 (`genai.Client(vertexai=True, ...).models.generate_content(...)`) ahead of the June 24, 2026 hard cutoff. `gemini-3.5-flash` itself is confirmed GA (released May 2026) and unaffected — only the legacy `vertexai` SDK package was deprecated. Exception handlers re-derived from the new SDK's actual tenacity retry predicate (`httpx.TimeoutException`, `httpx.ConnectError`) rather than guessed; the old six `google.api_core` exception classes are completely separate from `google.genai.errors` and would have silently stopped catching. Both XSS-S1 (excellent/100) and CMDI-S2 (failed/0) re-tested end to end through the new client; report quality identical. `google-genai>=2.9.0` added to `attense-app/requirements.txt`.

## 3. Known issues / open questions
- **Canonical thresholds locked in `live_thresholds.py`** — `cvss_base_score` and `detection_difficulty` for all 6 attack types (`APP-01` through `APP-06`) are hardcoded as constants, each independently verified against the S1 scenario block in the corresponding JSON file. These values are treated as approved by the cybersecurity team (they own the JSON files). If the cybersecurity team updates a JSON file's CVSS score or difficulty rating, `CANONICAL_SCENARIOS` in `live_thresholds.py` must be updated to match.
- **Considered: local reference files for NIST/OWASP/MITRE passages** — Evaluated building local reference files with extracted passages from NIST SP 800-61, OWASP, and MITRE ATT&CK (instead of just the one-line `mapping_note`/`note` already in the rule JSON files) so Gemini's reports could cite deeper standard-specific guidance. Decided to defer — the `scoring_rules` breakdown already gives Gemini enough specific, actionable evidence per rule (what was missing, what the timing gap was) to explain failures and improvements without this. Revisit after the rest of the pipeline (full integration, all 6 attack types live-tested) is working end to end. If revisited: this is additive polish/credibility, not load-bearing — the rule evidence is the actual substance.
- **`incident_ended` missing from "good response" scenario fixtures** — All 6 attack JSON files' complete-response scenarios (e.g. XSS-S1, XSS-S3 style) are missing an `incident_ended` event in their `event_log`. Without it, `outcome.py` can never return `"SUCCESS"` — only `"INCOMPLETE"` — even when `scoring_engine.py` correctly grades the response as `excellent`. This is a test-fixture/rule-file data gap, not a code bug in `bridge.py`, `report.py`, or `scoring_engine.py`. Needs `incident_ended` added to each file's complete-response scenarios. Worth deciding whether this is something the AI team patches directly in the JSON files, or flags to the cybersecurity team since they own those files.

## 4. Key architectural facts

### Scoring formula (from schema v2.0.0)
```
final_score = clamp(round((100 + penalty_total) * ttc_factor + response_difficulty_bonus, 2), 0, 100)
```
- `ttc_factor`: 1.0 if `containment_succeeded ≤ ttc_expected_sec`; linear decay to 0.0 between `ttc_expected_sec` and `ttc_max_sec`; 0.0 if absent or later than `ttc_max_sec`.
- `ttc_expected_sec = max(900, 3600 * (10 - cvss_base_score))`
- `ttc_max_sec = ttc_expected_sec * 1.5`
- `response_difficulty_bonus = min(4500 * difficulty_numeric / max(investigation_delay_sec, 1), 25)` — only when `containment_succeeded` present; difficulty_numeric: low=1, medium=2, high=3, very_high=4.
- `investigation_delay_sec` = `t_offset` of `alert_investigation_started` (alert_raised is always t=0).
- MTTA threshold is keyed to `detection.difficulty`, NOT `alert_severity`.

### Rule dependency semantics (R01–R09)
- R01: `alert_investigation_started` after mtta_threshold OR absent → −15
- R02: neither `incident_confirmed` nor `dismissal_approved` present → −15
- R03: `incident_confirmed` present AND (`evidence_preserved` absent OR after `containment_initiated`) → −10
- R04: `containment_initiated` absent OR after `ttc_max_sec` → −25
- R05: `containment_succeeded` absent → −30
- R06: `containment_succeeded` present AND (`eradication_completed` absent OR out of order) → −10
- R07: `eradication_completed` present AND (`recovery_validated` absent OR out of order) → −10
- R08: `recovery_validated` present AND (`lessons_learned_recorded` absent OR out of order) → −5
- R09: `alert_denied` present for `alert_severity` **medium or higher** without preceding `dismissal_approved` → −20
- R03–R08: each fires only when its prerequisite event is present (conditional, not cascading).
- R09 is severity-gated: fires only for medium/high/very_high; "low" severity `alert_denied` does NOT trigger it.

### Verdict bands
| Band | Score range |
|------|-------------|
| excellent | 90–100 |
| acceptable | 70–89.99 |
| needs_review | 50–69.99 |
| failed | 0–49.99 |

### Gemini client (google-genai SDK)
`report_generator.py` uses `google-genai` 2.9.0 (not the legacy `vertexai` package). Setup pattern:
```python
from google import genai
from google.genai import errors as genai_errors
client = genai.Client(vertexai=True, project=VERTEX_PROJECT_ID, location=VERTEX_LOCATION)
response = client.models.generate_content(model=VERTEX_MODEL, contents=prompt)
```
Auth is ADC-based (`google.auth.credentials`) — same `gcloud auth application-default login` path as before. No `vertexai.init()` call. Exception hierarchy is `genai_errors.ClientError` (all 4xx, branch on `exc.code`) / `genai_errors.ServerError` (5xx) / `genai_errors.APIError` (base); network-level failures after retry exhaustion are `httpx.TimeoutException` or `httpx.ConnectError` (the SDK's tenacity predicate names these explicitly). The old `google.api_core.exceptions.*` classes are a completely separate hierarchy and do not catch anything from this SDK.

### Live-incident threshold resolution
`attense-app/ATTENSE_app/AI/live_thresholds.py` is the single source of truth for canonical `cvss_base_score` and `detection_difficulty` per attack type. `compute_live_thresholds("APP-0X")` returns all three thresholds needed by the scoring engine. `bridge.py` calls it when `scenario_id` doesn't match any scenario block in the rule JSON (i.e., every real live incident). Alert severity for R09 is read from `alert_raised` event `metadata["severity"]` and normalised through `_SEVERITY_NORMALIZE` (`"critical"` → `"very_high"`) before being placed in the synthetic scenario dict.

### Key file locations
| File | Purpose |
|------|---------|
| `attense-app/ATTENSE_app/AI/Data/APP-01-XSS.json` | Attack rule + scenario dataset (schema v2.0.0) |
| `attense-app/ATTENSE_app/AI/live_thresholds.py` | Canonical cvss/difficulty per attack type + threshold computation |
| `attense-app/ATTENSE_app/blueteam/events/allowed_events.py` | Canonical allowed event type list |
| `attense-app/ATTENSE_app/blueteam/config/constants.py` | Event type constants |
| `attense-app/ATTENSE_app/blueteam/core/blueactions/hive_keywords.py` | Keyword regex (shared by translator + extractor) |
| `attense-app/ATTENSE_app/blueteam/core/blueactions/hive_event_translator.py` | TheHive → internal event translation |
| `attense-app/ATTENSE_app/blueteam/core/blueactions/analyst_action_extractor.py` | NLP extraction of analyst actions |
| `attense-app/ATTENSE_app/blueteam/core/blueactions/post_incident_actions.py` | Post-incident event handlers |
| `attense-app/ATTENSE_app/blueteam/api/webhook_router.py` | Webhook ingestion (includes self-approval guard) |
| `attense-app/pipeline/bridge.py` | Evaluation pipeline bridge (live routing + synthetic scenario logic) |
| `attense-app/pipeline/scoring_engine.py` | R01–R09 rule evaluation, penalty + score computation |
| `attense-app/pipeline/report_generator.py` | Gemini markdown report generator (7-section prompt) |
| `watcher/agent.py` | Watcher agent |
| `test_full_cycle.py` | Full-cycle integration test (untracked) |

### Event types in scope (schema v2.0.0)
`alert_raised`, `alert_investigation_started`, `alert_denied`, `incident_confirmed`, `dismissal_approved`, `evidence_preserved`, `containment_initiated`, `containment_succeeded`, `eradication_completed`, `recovery_validated`, `lessons_learned_recorded`

## 5. Next step
**Full end-to-end Gemini test with a live-style incident (`scenario_id="APP-01"`)** inside the `attense_app` container. Adapt `run_gemini_test.py` (or write a parallel script) to build a synthetic live incident with a bare `APP-01` scenario_id and `metadata["severity"]` on the `alert_raised` event, run the full `run_bridge()` → `generate()` chain, and confirm:
1. The synthetic scenario path produces a coherent Gemini report (Score Breakdown, Attack Context, Assessment sections all populated).
2. No crash or silent fallback anywhere in the live path under Gemini conditions.
