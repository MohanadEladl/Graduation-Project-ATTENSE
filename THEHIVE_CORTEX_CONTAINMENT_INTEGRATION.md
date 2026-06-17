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
  - Starts `cortex` using `thehiveproject/cortex:3.1.7-1`.
  - Mounts local responders into Cortex with `./cortex/responders:/opt/cortex/responders`.
  - Starts `cortex-init`, which configures Cortex, enables the responder, patches TheHive, and restarts TheHive.

- `thehive/application.conf`
  - Configures TheHive webhooks:
    - `notification.notifier.webhook.default.url = "http://attense-app:8010/internal/webhook/hive"`
    - `notification.notifier.active = ["webhook"]`
  - Configures TheHive to talk to Cortex:
    - `url = "http://cortex:9001"`
    - `key = "attense-cortex-key"` initially, then patched by setup automation.

- `cortex/application.conf`
  - Enables local authentication.
  - Enables process and Docker job runners.
  - Sets the responder path to `/opt/cortex/responders`.

- `cortex/responders/WazuhBlockIP/WazuhBlockIP.json`
  - Defines the Cortex responder.
  - Restricts it to `ip` observables with `dataTypeList: ["ip"]`.
  - Runs `python3 WazuhBlockIP/wazuh_block_ip.py`.

- `cortex/responders/WazuhBlockIP/wazuh_block_ip.py`
  - Reads the observable IP from Cortex stdin input.
  - Authenticates to Wazuh at `https://wazuh-manager:55000`.
  - Calls Wazuh `PUT /active-response`.
  - Sends command `firewall-drop` to agent `001`.
  - Returns Cortex-compatible JSON with success or error status.

- `scripts/setup_cortex.py`
  - Waits for Cortex.
  - Creates admin and organization users.
  - Generates a Cortex API key.
  - Enables `WazuhBlockIP` for the ATTENSE organization.
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

The current Cortex responder supports only one real containment action:

- `WazuhBlockIP`
  - Input: IP observable.
  - Enforcement: Wazuh `firewall-drop`.
  - ATTENSE event result: responder action status maps to containment success/failure.

If the requirement is that TheHive should contain all ATTENSE containment actions through Cortex, then the responder set should be expanded so each action has a responder or a parameterized responder:

| ATTENSE strategy | Suggested Cortex responder | Enforcement target |
|---|---|---|
| `block_ip` | `WazuhBlockIP` | Wazuh Active Response |
| `kill_process` | `WazuhKillProcess` | Wazuh custom active response or target-agent |
| `disable_service` | `WazuhDisableService` | Wazuh custom active response or target-agent |
| `isolate_host` | `WazuhIsolateHost` | Wazuh custom active response or target-agent |
| `block_request` | `AppBlockRequest` | target-agent or reverse proxy |
| `disable_endpoint` | `AppDisableEndpoint` | target-agent/application control |
| `block_path` | `AppBlockPath` | target-agent/application control |
| `invalidate_session` | `AppInvalidateSession` | application control |

The cleaner design is one responder per high-risk containment action, because each action has different parameters, validation, and rollback behavior. A single generic "run containment" responder is possible, but it is easier to misuse and harder to audit.

Do not attach these responders to rules that auto-run on alert creation. They should be available to the analyst, but execution should remain a deliberate analyst action.

## Recommended Improvements

1. Keep `WazuhBlockIP` as the first production responder.
2. Add one Cortex responder per containment action that should be available in TheHive.
3. Keep responders manually launched during measured exercises; do not auto-run blocking or isolation from alert rules, enrichment jobs, or response coordinators.
4. Make every responder return structured Cortex JSON with:
   - `success`
   - `message`
   - `artifacts`
   - `errorMessage` on failure
5. Add responder output details into ATTENSE event metadata where possible.
6. Avoid hard-coded Wazuh agent IDs. `wazuh_block_ip.py` currently sends to agent `001`; this should come from responder configuration or observable/context metadata.
7. Move Wazuh credentials out of the responder source code and into Cortex responder configuration or environment variables.
8. Add webhook authentication/HMAC validation before trusting TheHive webhook payloads.
9. Normalize strategy names. `defense_profiles.json` contains names like `sanitize_input`, `block_input`, `remove_file`, and `disable_account`, but `TargetConnector` currently supports different names such as `remove_payload`, `lock_account`, and `restrict_access`.

## Validation Checklist

Use this checklist to confirm the integration works:

1. Start the stack with `docker compose up -d`.
2. Confirm Cortex is healthy at `http://localhost:9001`.
3. Confirm TheHive is reachable at `http://localhost:9000`.
4. Confirm `scripts/setup_cortex.py` has run successfully.
5. Confirm `thehive/application.conf` has a real Cortex API key, not the placeholder.
6. Confirm `WazuhBlockIP` is enabled in Cortex for the ATTENSE organization.
7. Create or import a TheHive case with tag `attense:incident-<incident_id>`.
8. Add an IP observable.
9. Have the analyst choose and run `WazuhBlockIP` from TheHive.
10. Confirm ATTENSE receives `ResponderAction/Create` and emits `containment_initiated`.
11. Confirm Wazuh receives the active response request.
12. Confirm TheHive emits `ResponderAction/Update`.
13. Confirm ATTENSE emits `containment_succeeded` or `containment_failed`.

## Summary

The repository already integrates containment through TheHive and Cortex correctly at the architecture level:

- TheHive is configured to call Cortex.
- Cortex has a mounted `WazuhBlockIP` responder.
- The responder triggers Wazuh Active Response only when the analyst launches it.
- TheHive webhooks call ATTENSE.
- ATTENSE translates responder lifecycle events into containment lifecycle events.

The remaining work is to expand the responder library beyond IP blocking, remove hard-coded Wazuh values, secure webhook and credential handling, and normalize strategy names across `defense_profiles.json`, `TargetConnector`, Cortex responder names, and TheHive analyst actions.
