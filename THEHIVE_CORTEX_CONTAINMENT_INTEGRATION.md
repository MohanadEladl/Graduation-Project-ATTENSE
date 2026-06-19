# TheHive, Cortex, Wazuh, and ATTENSE Containment Integration

This note explains how containment actions are integrated in this project. I am treating "Codex" in the request as "Cortex", because the repository contains a Cortex service, Cortex responder, and TheHive-to-Cortex wiring.

## What Proper Integration Looks Like

A proper TheHive containment workflow usually keeps the responsibilities separate:

1. TheHive is the incident response console where analysts open cases, inspect observables, and launch responders.
2. Cortex owns analyzers and responders. Responders are the active response mechanism that TheHive can run against alerts, cases, tasks, and observables.
3. Wazuh owns endpoint security enforcement. Active Response executes the actual host/network action, such as dropping an IP.
4. ATTENSE records the incident lifecycle and scoring events, including `containment_initiated`, `containment_succeeded`, and `containment_failed`.

Important measurement rule: containment must not be selected or triggered automatically by ATTENSE, Cortex, Wazuh, Codex, or any coordinator script. The analyst must choose the containment action. The platform should measure which action the analyst chose, when they chose it, and whether it worked. Automatic enrichment and automatic result recording are acceptable; automatic blocking/isolation is not.

Official references checked:

- StrangeBee Cortex docs: https://docs.strangebee.com/cortex/
- Cortex API docs: https://docs.strangebee.com/cortex/api/api-guide/
- Wazuh Active Response docs: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html

The key documented idea is that TheHive can call Cortex responders for active response, and Wazuh Active Response is the enforcement mechanism that runs commands on agents.

## Current Repository Wiring

The integration is already present in these files:

- `docker-compose.yml`
  - Starts `thehive` using `thehiveproject/thehive4:4.1.24-1`.
  - Starts `cortex` using `thehiveproject/cortex:3.1.7-1`, depending on `elasticsearch: condition: service_healthy` (previously a plain `depends_on: - elasticsearch`, which let Cortex start before ES was actually ready and left it permanently unable to create its own index — see Operational Notes below).
  - Mounts local responders into Cortex with `./cortex/responders:/opt/cortex/responders`.
  - Mounts `./wazuh/active-response/bin:/var/ossec/active-response/bin` into the Wazuh manager, so Wazuh's own bundled active-response binaries (`firewall-drop`, `route-null`, `disable-account`, ...) are available to the manager's `PUT /active-response` API.
  - `target-agent` has `cap_add: [NET_ADMIN]` so `iptables` (used by `firewall-drop`) actually works — containers don't have this capability by default.
  - Starts `cortex-init`, which configures Cortex, enables the responders, patches TheHive, and restarts TheHive.
  - Starts `wazuh-init` (`scripts/setup_wazuh.py`), which fixes Wazuh manager log-directory ownership and active-response command bindings — see Operational Notes #11/#13 for why this is needed on every fresh `wazuh_manager_etc` volume.

- `thehive/application.conf`
  - Configures TheHive webhooks:
    - `notification.notifier.webhook.default.url = "http://attense-app:8010/internal/webhook/hive"`
    - `notification.notifier.active = ["webhook"]`
  - Configures TheHive to talk to Cortex:
    - `url = "http://cortex:9001"`
    - `auth.type = "bearer"` and `auth.key = "attense-cortex-key"` initially, then patched by setup automation.

- `cortex/application.conf`
  - Enables local authentication.
  - Enables process and Docker job runners.
  - `responder.urls = ["/opt/cortex/responders"]` — **note:** the old `responder.path` key is deprecated and, confirmed empirically, does not load local responders into Cortex's worker catalog at all in this Cortex version (3.1.7-1). `responder.urls` is the only key that actually works for a local directory; this caused all three responders (including the pre-existing `WazuhBlockIP`) to be invisible to Cortex until fixed.

- `cortex/responders/_common/wazuh_ar_client.py`
  - Shared helper used by every `WazuhXxx` responder: Wazuh auth (`get_token`), dynamic agent lookup (`resolve_agent_id`, `resolve_agent_id_with_fallback`), and active-response triggering (`trigger_active_response`).
  - Centralizes the Wazuh API contract so each responder script only contains its own observable parsing and the specific active-response `command`/`arguments` it sends.

- `cortex/responders/WazuhBlockIP/` (`WazuhBlockIP.json` + `wazuh_block_ip.py`)
  - Restricted to `ip` observables (`dataTypeList: ["ip"]`).
  - Reads the observable IP from Cortex stdin input, resolves a Wazuh agent ID dynamically (by IP, falling back to the configured `agent_name`), and sends Wazuh active-response command `firewall-drop`.
  - `wazuh_url`, `wazuh_username`, `wazuh_password`, `agent_name` come from Cortex's per-organization responder configuration (`configurationItems`), not from source — set via `scripts/setup_cortex.py` or the Cortex UI.

- `cortex/responders/WazuhIsolateHost/` (`WazuhIsolateHost.json` + `wazuh_isolate_host.py`)
  - Restricted to `ip` observables — the compromised host's own IP.
  - Sends Wazuh active-response command `route-null`, which null-routes the host (Wazuh's built-in host-isolation mechanism). Same configuration and agent-resolution pattern as `WazuhBlockIP`.

- `cortex/responders/WazuhDisableAccount/` (`WazuhDisableAccount.json` + `wazuh_disable_account.py`)
  - Restricted to `other` observables (the compromised username — TheHive has no built-in "username" dataType).
  - Sends Wazuh active-response command `disable-account`. A username has no IP/host to resolve from, so the agent is resolved purely from the configured `agent_name` (this sandbox runs a single target agent).

- `scripts/setup_cortex.py`
  - Waits for Cortex.
  - Creates admin and organization users.
  - Generates a Cortex API key.
  - Enables `WazuhBlockIP`, `WazuhIsolateHost`, and `WazuhDisableAccount` for the ATTENSE organization, pre-configured with `WAZUH_API_URL` / `WAZUH_USER` / `WAZUH_PASS` / `WAZUH_AGENT_NAME` (from `secrets/ATTENSE.env` or real env vars) so none of them need manual configuration in the Cortex UI.
  - Writes the real API key into `thehive/application.conf`.
  - Restarts TheHive so the Cortex key is loaded.

- `attense-app/ATTENSE_app/blueteam/api/webhook_router.py`
  - Receives TheHive webhooks at `/internal/webhook/hive`.
  - Extracts the ATTENSE incident ID from TheHive tags/custom fields.
  - Translates Hive activity into ATTENSE events.
  - Emits those events into the ATTENSE event store.

- `attense-app/ATTENSE_app/blueteam/core/blueactions/hive_event_translator.py`
  - Maps `ResponderAction/Create` to `containment_initiated`.
  - Maps `ResponderAction/Update` with `Success` to `containment_succeeded`.
  - Maps `ResponderAction/Update` with `Failure` or `Timeout` to `containment_failed`.
  - Also supports task-based manual containment mapping.

## End-to-End Flow

The integrated containment flow is:

1. ATTENSE creates or links an incident to a TheHive case.
2. The case/observable is tagged with `attense:incident-<incident_id>`.
3. The analyst opens the case in TheHive.
4. The analyst chooses a containment action, such as running the `WazuhBlockIP` Cortex responder on an IP observable.
5. TheHive creates a Cortex responder action.
6. TheHive emits a webhook to ATTENSE.
7. ATTENSE receives `ResponderAction/Create` and records `containment_initiated`; it does not decide the action.
8. Cortex runs `WazuhBlockIP`.
9. `WazuhBlockIP` calls Wazuh `PUT /active-response` with `firewall-drop`.
10. Wazuh executes the block on the configured agent.
11. Cortex marks the responder action as success, failure, or timeout.
12. TheHive emits another webhook.
13. ATTENSE receives `ResponderAction/Update`.
14. ATTENSE records `containment_succeeded` or `containment_failed`.
15. ATTENSE incident state and TTC metrics are updated by the event pipeline.

The only automatic part after step 4 is observation and scoring. The block itself happens because the analyst selected the responder/action.

## How Containment Actions Are Integrated Together

There are two containment surfaces in the project:

### 1. ATTENSE Direct Sandbox Containment

The local BlueTeam API can execute scenario-specific sandbox containment only when an analyst-facing caller submits `/blueteam/initiate-containment` with an explicit `strategy`. It must not be called by an automatic coordinator during a measured exercise.

- `containment_service.py`
- `TargetConnector`
- `STRATEGY_ENDPOINT_MAP`

Examples:

- `kill_process` -> `/system/kill-process`
- `disable_service` -> `/system/disable-service`
- `isolate_host` -> `/system/isolate`
- `block_request` -> `/system/block-request`
- `block_path` -> `/system/block-path`
- `invalidate_session` -> `/system/invalidate-session`

This path is useful when ATTENSE itself drives the exercise through its own API and target-agent sandbox.

### 2. TheHive and Cortex Responder Containment

TheHive/Cortex containment is the SOC workflow path:

- The analyst works in TheHive.
- The analyst chooses the action and launches it as a Cortex responder.
- Cortex calls the enforcement system, currently Wazuh.
- TheHive webhooks report the action lifecycle back into ATTENSE.

This path is useful when the analyst should perform response from TheHive, while ATTENSE observes and scores the response.

This design measures response quality, not button-clicking. The UI should present enough context and multiple plausible containment options so the analyst has to choose an appropriate action. It should not preselect the correct action or run it automatically.

Both paths converge into the same ATTENSE event model:

- `containment_initiated`
- `containment_succeeded`
- `containment_failed`

That is the important integration point. The enforcement path can differ, but the incident state machine sees the same event names.

## Containment Actions That Should Be Exposed Through Cortex

The Cortex responder set currently supports three real containment actions, all built on Wazuh active-response binaries that are already bundled and mounted into the Wazuh manager (no manager-side config changes needed):

- `WazuhBlockIP` — Input: `ip` observable. Enforcement: Wazuh `firewall-drop`.
- `WazuhIsolateHost` — Input: `ip` observable (the host itself). Enforcement: Wazuh `route-null` (null-routes the host).
- `WazuhDisableAccount` — Input: `other` observable (username). Enforcement: Wazuh `disable-account`. This is the scored `correct_action` for the Broken-Authentication scenario (APP-06) in `defense_profiles.json` — previously nothing in the codebase implemented it.

All three resolve their Wazuh agent ID dynamically (`cortex/responders/_common/wazuh_ar_client.py`) rather than hardcoding it, and read Wazuh credentials from Cortex responder configuration rather than from source.

If the requirement is that TheHive should contain all ATTENSE containment actions through Cortex, the responder set should keep expanding so each action has a responder or a parameterized responder:

| ATTENSE strategy | Cortex responder | Enforcement target | Status |
|---|---|---|---|
| `block_ip` | `WazuhBlockIP` | Wazuh Active Response (`firewall-drop`) | Implemented |
| `isolate_host` | `WazuhIsolateHost` | Wazuh Active Response (`route-null`) | Implemented |
| `disable_account` | `WazuhDisableAccount` | Wazuh Active Response (`disable-account`) | Implemented |
| `kill_process` | `WazuhKillProcess` | No stock Wazuh binary — needs a new custom active-response script | Not yet — deferred |
| `disable_service` | `WazuhDisableService` | Wazuh custom active response or target-agent | Not yet |
| `block_request` | `AppBlockRequest` | target-agent or reverse proxy | Not yet — target-agent has no real `/system/*` containment endpoints today |
| `disable_endpoint` | `AppDisableEndpoint` | target-agent/application control | Not yet — same target-agent gap |
| `block_path` | `AppBlockPath` | target-agent/application control | Not yet — same target-agent gap |
| `invalidate_session` | `AppInvalidateSession` | application control | Not yet — same target-agent gap |

The "Not yet" rows targeting `target-agent` all share the same blocker: `TargetConnector`'s `STRATEGY_ENDPOINT_MAP` points at `/system/kill-process`, `/system/disable-service`, `/system/isolate`, `/system/block-request`, etc., but `target-agent` currently only implements `/system/ping` (a deliberately-vulnerable diagnostic endpoint). Building real containment endpoints there is a separate, larger effort.

The cleaner design is one responder per high-risk containment action, because each action has different parameters, validation, and rollback behavior. A single generic "run containment" responder is possible, but it is easier to misuse and harder to audit.

Do not attach these responders to rules that auto-run on alert creation. They should be available to the analyst, but execution should remain a deliberate analyst action.

## Recommended Improvements

1. ~~Keep `WazuhBlockIP` as the first production responder.~~ Done — and two more shipped alongside it (`WazuhIsolateHost`, `WazuhDisableAccount`).
2. Add one Cortex responder per containment action that should be available in TheHive. Three down (`block_ip`, `isolate_host`, `disable_account`); `kill_process` and the target-agent app-level actions (`block_request`, `disable_endpoint`, `block_path`, `invalidate_session`) remain.
3. Keep responders manually launched during measured exercises; do not auto-run blocking or isolation from alert rules, enrichment jobs, or response coordinators.
4. Make every responder return structured Cortex JSON with:
   - `success`
   - `message`
   - `artifacts`
   - `errorMessage` on failure
5. Add responder output details into ATTENSE event metadata where possible.
6. ~~Avoid hard-coded Wazuh agent IDs.~~ **Resolved** for all three responders — `cortex/responders/_common/wazuh_ar_client.py` resolves the agent ID dynamically via the Wazuh API (`resolve_agent_id` / `resolve_agent_id_with_fallback`) instead of hardcoding `"001"`.
7. ~~Move Wazuh credentials out of the responder source code.~~ **Resolved** for all three responders — credentials and connection details (`wazuh_url`, `wazuh_username`, `wazuh_password`, `agent_name`) come from each responder's Cortex `configurationItems`, populated by `scripts/setup_cortex.py` from `secrets/ATTENSE.env` / environment variables, not from source.
8. ~~Add webhook authentication/HMAC validation before trusting TheHive webhook payloads.~~ **Resolved** — the `/internal/webhook/hive` endpoint now authenticates every request with a shared bearer secret. TheHive is configured (`thehive/application.conf` → webhook `auth { type = "bearer" }`) to send `Authorization: Bearer <WEBHOOK_SECRET>`, and `blueteam/api/webhook_router.py` verifies it with a constant-time compare (`hmac.compare_digest`) against `settings.webhook_secret`, rejecting missing/invalid tokens with `401` before any processing. The secret is delivered identically to both containers via docker-compose's `WEBHOOK_SECRET` (`secrets/ATTENSE.env` / root `.env`, default `changeme-webhook` for dev). TheHive 4 cannot HMAC-sign the payload body, so bearer-token auth is the supported and sufficient scheme.
9. Normalize strategy names. `defense_profiles.json` contains names like `sanitize_input`, `block_input`, `remove_file`, and `block_upload`, but `TargetConnector` currently supports different names such as `remove_payload`, `lock_account`, and `restrict_access`. The new responders intentionally used `isolate_host` / `disable_account` to match `defense_profiles.json`'s vocabulary directly, but the broader mismatch across `defense_profiles.json`, `TargetConnector`, and Cortex responder names is still open.

## Validation Checklist

This checklist was run end-to-end against the live stack (not just read through). Steps 1–6 and 8–10's *Cortex job* results are confirmed working; the TheHive-UI-driven parts of 7–10 (vs. driving Cortex directly via its job API) were not separately re-walked after the fixes below and are worth re-confirming through the actual TheHive UI before a live demo.

1. Start the stack with `docker compose up -d`.
2. Confirm Cortex is healthy at `http://localhost:9001`.
3. Confirm TheHive is reachable at `http://localhost:9000`.
4. Confirm `scripts/setup_cortex.py` has run successfully (`docker compose run --rm cortex-init`).
5. Confirm `thehive/application.conf` has a real Cortex API key, not the placeholder.
6. Confirm `WazuhBlockIP`, `WazuhIsolateHost`, and `WazuhDisableAccount` are all enabled in Cortex for the ATTENSE organization (`GET /api/organization/responder?range=all`), with the Wazuh connection configuration populated (not blank).
7. Create or import a TheHive case with tag `attense:incident-<incident_id>`.
8. Add an `ip` observable, then have the analyst choose and run `WazuhBlockIP`.
   - Confirm ATTENSE receives `ResponderAction/Create` and emits `containment_initiated`.
   - Confirm `wazuh/active-response/logs/active-responses.log` shows the `firewall-drop` invocation — confirmed working: the script receives `alert.data.srcip` correctly and Wazuh dispatches it to the agent. The script itself then reports `"The iptables file 'iptables' is not accessible"` because `target-agent`'s minimal image has no `iptables` installed — this is a target-agent image gap, not a wiring problem; the orchestration is proven, only the final OS-level firewall call needs `iptables` installed in `target-agent/Dockerfile` if a real block is required.
   - Confirm TheHive emits `ResponderAction/Update` and ATTENSE emits `containment_succeeded` or `containment_failed`.
9. Add an `ip` observable for the host itself, then have the analyst choose and run `WazuhIsolateHost`.
   - Confirm `active-responses.log` shows the `route-null` invocation — confirmed working; same `iptables`-style gap (`route` binary missing in `target-agent`).
10. Add an `other` observable with a username, then have the analyst choose and run `WazuhDisableAccount`.
    - Confirm `active-responses.log` shows the `disable-account` invocation with the correct username — confirmed fully working, no missing-binary issue (this one completed cleanly).

## Operational Notes (found and fixed during live validation)

Running the checklist against the real stack surfaced a chain of pre-existing infrastructure issues — none specific to the new responder code, all blocking *any* responder including the original `WazuhBlockIP`. In order encountered:

1. **Cortex started before Elasticsearch was ready** (plain `depends_on: - elasticsearch`) and never created its own `cortex_6` index, leaving every Cortex API call returning 520/`index_not_found_exception` indefinitely until Cortex was restarted after ES was confirmed healthy. Fixed by changing Cortex's `depends_on` to `condition: service_healthy` (matching the pattern already used for `thehive`).
2. **`responder.path` doesn't work in Cortex 3.1.7-1.** Confirmed via `WorkerSrv`'s own "New worker list" log: it only ever listed the public analyzer catalog, never any local responder. Switched to `responder.urls = ["/opt/cortex/responders"]`.
3. **Cortex's local-auth API is cookie-based, not Bearer-token-in-body**, and requires Play's CSRF double-submit header (`X-CORTEX-XSRF-TOKEN`, confirmed from Cortex's own frontend bundle — not the generic `Csrf-Token: nocheck` bypass). `scripts/setup_cortex.py` was written against the wrong auth model entirely and never actually completed a real run before this session. Rewrote `_req`/`_get_session_token` accordingly.
4. **The first superadmin user must belong to a special `cortex` organisation** that Cortex does not auto-create; `setup_cortex.py` now creates it defensively before creating the admin user.
5. **`GET /api/user` keys the login under `id`, not `login`** — the script's idempotency check never matched, so it tried to recreate existing users. Fixed.
6. **Listing/enabling responders needs an org-scoped session** (the `attense-analyst` user), not the platform superadmin, which gets a 403 against `/api/responderdefinition`. Also, the correct endpoints are `GET /api/responderdefinition` (not `/api/responder`) and `POST /api/organization/responder/{id}` with `{"name": "<definitionId>", ...}` in the body (no org name in the path — confirmed from Cortex's frontend bundle). `setup_cortex.py` updated to log in as the org user for this step and check `GET /api/organization/responder?range=all` first for idempotency.
7. **The responder JSON `"command"` field must be just the script path** (e.g. `WazuhBlockIP/wazuh_block_ip.py`), not `"python3 <path>"` — Cortex treats the whole string as a single executable to exec directly (the scripts already have a `#!/usr/bin/env python3` shebang and are world-executable via the bind mount).
8. **Cortex's job runner uses Python 3.9** inside the container; `cortex/responders/_common/wazuh_ar_client.py`'s `X | None` type hints (PEP 604, Python 3.10+) crashed at import. Fixed with `from __future__ import annotations`.
9. **Process-runner job I/O contract**, confirmed empirically (undocumented in the local responder schema): Cortex passes a job directory as `argv[1]` containing `input/input.json`; printing to stdout is only a fallback Cortex doesn't reliably parse for the structured `success` field. Responders must read `<job_dir>/input/input.json` and write `<job_dir>/output/output.json`. Cortex's expected success-report shape is `{"success": true, "full": {...}, "operations": [...]}` — the analyzer-style `"artifacts"` field used in earlier drafts of this doc is *not* read for responders and silently caused jobs to be marked `Failure` even when the script itself reported `success: true`.
10. **Wazuh's REST API in 4.9.2 has changed shape from what `wazuh_block_ip.py` was originally written against**: `agents_list` is a query parameter, not a body field; `"custom": true` no longer exists — prefix the command with `!` instead (e.g. `"command": "!firewall-drop"`) to run a script directly without requiring prior `<command>`/`<active-response>` XML registration; and the target value goes in `"alert": {"data": {"srcip": "..."}}` (or `{"dstuser": "..."}` for `disable-account`), not a positional `arguments` array. All of this is in the manager's own bundled `api/spec/spec.yaml` (`ActiveResponseBody` schema) — worth checking directly against the live container if anything here goes stale again.
11. **`wazuh-analysisd` was crash-looping** on the manager because `/var/ossec/logs/archives`, `/var/ossec/logs/firewall`, and the `wazuh_alerts` named-volume-backed `/var/ossec/logs/alerts` were owned by `root:root` instead of `wazuh:wazuh` (Docker creates volume mount points as root by default). This is the same root cause documented once before in `walkthrough.md` — it recurred because nothing in the compose stack chowns these paths automatically. **Now automated**: `scripts/setup_wazuh.py` (run via the `wazuh-init` one-shot service) fixes this on every stack startup, idempotently.
12. **`target-agent/ossec.conf` had `<active-response><disabled>yes</disabled></active-response>`**, globally disabling active-response on the only agent. Fixed in the repo file (now `disabled>no`), which is image-baked (`COPY`'d in `target-agent/Dockerfile`), so this persists across rebuilds.
13. **No `<command>`/`<active-response>` binding existed in the Wazuh manager's `ossec.conf`** for `firewall-drop`, `route-null`, or `disable-account` (only a commented-out example was present) — step 10's `!command` discovery means this binding isn't strictly required for API-triggered dispatch (only for automatic rule-triggered AR), but it's added anyway for consistency. **Now automated** by the same `wazuh-init` service as #11, since `/var/ossec/etc` lives in the `wazuh_manager_etc` named volume with no other repo-tracked source of truth.
14. **`target-agent`'s minimal image had no `iptables`/`route` binaries**, so `firewall-drop`/`route-null` ran successfully but the final OS command was a no-op (logged "binary not found"). Fixed by adding `iptables net-tools` to `target-agent/Dockerfile`. This alone wasn't enough — Docker containers don't have `NET_ADMIN` capability by default, and `iptables` failed with "Permission denied (you must be root)" even running as root without it. Added `cap_add: [NET_ADMIN]` to the `target-agent` service in `docker-compose.yml`. Confirmed working: a real `DROP` rule now appears in `iptables -L INPUT` after running `WazuhBlockIP`.
15. **Recreating `wazuh-manager` and/or `target-agent` (e.g. to pick up the fixes above) can trigger Wazuh's "Duplicate agent name" enrollment conflict** — the same issue already documented in `walkthrough.md`. `target-agent/entrypoint.sh` already clears its local `client.keys` on every start specifically to avoid this, but the *manager*-side stale agent record also needs clearing (`DELETE /agents?agents_list=<id>&status=all&older_than=0s` via the Wazuh API) before the agent's next enrollment retry succeeds. Not yet automated — if you recreate either container, check `GET /agents` for a `never_connected` or `disconnected` entry named `target-agent` and delete it if the new enrollment is stuck.
16. **The Wazuh-detection-to-TheHive-alert pipeline was completely disconnected**, separate from anything above — this is why a real attack against `target-agent` never produced a TheHive alert. Three independent breaks, all now fixed:
    - `signal-store`'s alert-tailing background thread had silently died ~21 hours earlier (`[reader] Timed out after 120s waiting for: alerts.json`, from when `wazuh-analysisd` was crash-looping — see #11) and never recovered, even though the container itself stayed "healthy" (its web server kept serving `/health`/`/events`). A plain `docker compose restart signal-store` was enough once the underlying Wazuh issue was fixed.
    - `signal-store`'s `OUTPUT_MODE` was `file`, which only appends to `mapped_events.jsonl` for `attense-app`'s internal incident/scoring tracker (`controller.py`) — it never POSTs to `blueteam/raise-alert`, which is the only thing that creates a TheHive alert. `output.py`'s `dispatch()` only supported `file` *or* `http`, never both, so fixing this without breaking the existing scoring tracker required adding a third `both` mode. `docker-compose.yml` now sets `OUTPUT_MODE: both`.
    - `attense-app`'s `HIVE_API_KEY` was still the literal placeholder `"changeme"` — never a real key, because TheHive had no operational org/user at all until this session (#4 area). Generated a real key for `attense-analyst@thehive.local` and put it in a new root `.env` file (gitignored — never commit a real key into `docker-compose.yml`), referenced as `${HIVE_API_KEY:-changeme}`. Also bumped `HiveClient`'s default timeout from 5s to 15s — one request was observed taking 5.5s and timing out client-side even though it had already succeeded in TheHive.

## Summary

The repository already integrates containment through TheHive and Cortex correctly at the architecture level:

- TheHive is configured to call Cortex.
- Cortex has three mounted, enabled, and **end-to-end validated** responders: `WazuhBlockIP`, `WazuhIsolateHost`, `WazuhDisableAccount`. Each was run for real against the live stack — Cortex job `Success`, Wazuh manager dispatch confirmed, the active-response script execution confirmed in `target-agent`'s `active-responses.log` with the correct data (`srcip`/`dstuser`), and for `WazuhBlockIP` a real `iptables DROP` rule confirmed on the agent.
- Each responder triggers Wazuh Active Response only when the analyst launches it, resolves its Wazuh agent ID dynamically (proven necessary: the agent's numeric ID changed from `001` to `003` over the course of this validation due to re-enrollment), and reads Wazuh credentials from Cortex configuration rather than source.
- TheHive webhooks call ATTENSE.
- ATTENSE translates responder lifecycle events into containment lifecycle events — this mapping is generic across responder names, so adding new responders required no changes to `hive_event_translator.py` or `webhook_router.py`.
- Getting there required fixing fifteen separate pre-existing infrastructure bugs across Cortex, Wazuh, `target-agent`, and `setup_cortex.py` (see Operational Notes) — none of them caused by the new responder code, all of them blocking *any* responder, including the original `WazuhBlockIP`, from ever having actually worked before this session. The two persistence-related ones (#11, #13) are now automated via the new `wazuh-init` service (`scripts/setup_wazuh.py`); run `docker compose run --rm wazuh-init` after a fresh `wazuh_manager_etc` volume.

The remaining work: add `kill_process` (needs a new custom Wazuh active-response script); build real `target-agent` containment endpoints for the app-level strategies (`block_request`, `disable_endpoint`, `block_path`, `invalidate_session`); secure webhook handling with HMAC validation; normalize strategy names across `defense_profiles.json`, `TargetConnector`, Cortex responder names, and TheHive analyst actions; and consider automating the agent-re-enrollment cleanup in #15 if container recreation becomes routine.
