# Blue Team Component — Function Reference

> Documentation for every Python file in the `blueteam/` service.
> Organized by architectural layer, matching the structure from **Blue team Component.docx**.

---

## Workflow Overview

```
[system] raise_alert()
              │
              ▼
[human] investigate_alert()
              │
       ┌──────┴──────┐
       ▼             ▼
 deny_alert()   confirm_incident()
 (false +ve)         │  ← TTD calculated here
                     ▼
            initiate_containment()
                     │
                     ▼
            complete_containment()
                     │  ← TTC calculated here
```

---

## `main.py`

Entry point — creates the FastAPI application.

| Symbol | Type | Description |
|--------|------|-------------|
| `app` | `FastAPI` | The application instance with title, description, and version. |
| `health()` | `GET /health` | Returns `{"status": "ok"}` — liveness check for container orchestrators. |

---

## `api/router.py`

**Traffic control only — no business logic.**
Every external caller reaches the Blue Team through this file.

| Function                        | Route                       | Description |
|---------------------------------|-----------------------------|---------------------------------------------------------|
| `api_raise_alert(body, emitter)` | `POST /blueteam raise-alert` | Passes SIEM alert data to `alert_service.raise_alert()`. Emits `alert_raised`. |
| `api_investigate_alert(body, emitter)` | `POST /blueteam/investigate-alert` | Passes triage request to `alert_service.investigate_alert()`. Emits `alert_investigation_started`. |
| `api_deny_alert(body, emitter)` | `POST /blueteam/deny-alert` | Passes false-positive decision to `alert_service.deny_alert()`. Emits `alert_denied`. Incident ends here — no TTD. |
| `api_confirm_incident(body, emitter, hive)` | `POST /blueteam/confirm-incident` | Passes confirmation to `incident_service.confirm_incident()`. **TTD is calculated here.** Emits `incident_confirmed`. |
| `api_initiate_containment(body, emitter, sandbox)` | `POST /blueteam/initiate-containment` | Passes containment request to `containment_service.initiate_containment()`. Emits `containment_initiated`. |
| `api_complete_containment(body, emitter)` | `POST /blueteam/complete-containment` | Passes completion to `containment_service.complete_containment()`. System evaluates outcome. Emits `containment_succeeded` or `containment_failed`. |

---

## `api/dependencies.py`

Dependency injection providers — supplies shared components via FastAPI `Depends()`.

| Function | Returns | Description |
|----------|---------|-------------|
| `get_settings()` | `Settings` | Returns a **cached** `Settings` singleton (reads env vars once on first call). |
| `get_event_emitter()` | `EventEmitter` | Returns the single shared `EventEmitter` used by all routes. |
| `get_hive_client()` | `HiveClient` | Creates a `HiveClient` configured from settings (Hive URL + API key). |
| `get_sandbox_connector()` | `TargetConnector` | Creates a `TargetConnector` configured with the sandbox URL from settings. |
| `get_logger()` | `logging.Logger` | Returns the `blueteam.audit` logger for audit trail entries. |

---

## `api/middleware.py`

Cross-cutting concerns that run **automatically before/after every request**.

### `RequestLoggingMiddleware`

| Method | Description |
|--------|-------------|
| `dispatch(request, call_next)` | Logs every request (method + path), attaches a unique `X-Request-ID` header, and logs response status + latency in milliseconds. |

### `TimingMiddleware`

| Method | Description |
|--------|-------------|
| `dispatch(request, call_next)` | Measures total processing time and attaches it as the `X-Process-Time` header (e.g. `0.0031s`). |

---

## `core/services/alert_service.py`

Business logic for all alert-related analyst actions.

| Function | Emits | Description |
|----------|-------|-------------|
| `raise_alert(body, emitter)` | `alert_raised` | Simulates SIEM detecting an anomaly. Validates incident not terminal and no duplicate alert. Builds and persists the event. |
| `investigate_alert(body, emitter)` | `alert_investigation_started` | Analyst picks up alert for triage. Validates `alert_raised` exists and investigation not yet started. |
| `deny_alert(body, emitter)` | `alert_denied` | Analyst marks alert as false positive. Validates investigation was started and incident not already confirmed. Incident ends here — no TTD. |

---

## `core/services/incident_service.py`

Business logic for incident confirmation — the critical TTD step.

| Function | Emits | Description |
|----------|-------|-------------|
| `confirm_incident(body, emitter, hive)` | `incident_confirmed` | Analyst confirms true positive. **TTD anchor — calculated as `detection_time − start_time`.** Updates Hive case severity. Status → `DETECTED`. |

---

## `core/services/containment_service.py`

Business logic for the containment phase.

| Function | Emits | Description |
|----------|-------|-------------|
| `initiate_containment(body, emitter, sandbox)` | `containment_initiated` | Analyst triggers containment. Validates incident is `DETECTED`. Sends strategy command to sandbox. |
| `complete_containment(body, emitter)` | `containment_succeeded` or `containment_failed` | **System (not analyst) evaluates outcome** based on: (1) correct target? (2) within 5 minutes? Outcomes: `success`, `partial` (late), `failure` (wrong target). TTC recorded on success. |

---

## `core/validation/alert_validator.py`

Pre-condition guards — **invalid requests die here before reaching services**.

| Function | Guards | Description |
|----------|--------|-------------|
| `validate_raise_alert(incident, store)` | `raise_alert()` | Checks incident not terminal and no `alert_raised` already exists. |
| `validate_investigate_alert(incident, store)` | `investigate_alert()` | Checks incident not terminal, `alert_raised` exists, and `alert_investigation_started` does not exist yet. |
| `validate_deny_alert(incident, store)` | `deny_alert()` | Checks incident not terminal, investigation has started, and incident not already confirmed. |

---

## `core/validation/incident_validator.py`

| Function | Guards | Description |
|----------|--------|-------------|
| `validate_confirm_incident(incident, store)` | `confirm_incident()` | Checks: not terminal, investigation started, not denied, not already confirmed. |

---

## `core/validation/containment_validator.py`

| Function | Guards | Description |
|----------|--------|-------------|
| `validate_initiate_containment(incident, store)` | `initiate_containment()` | Checks incident is in `DETECTED` status and containment not already initiated. |
| `validate_complete_containment(incident, store)` | `complete_containment()` | Checks containment was initiated, incident not terminal, and no outcome event already exists. |

---

## `core/blueactions/alert_actions.py`

**Pure event-builder functions — no side effects. Only construct and return `Event` objects.**

| Function | Event Type | Description |
|----------|-----------|-------------|
| `_new_event_id()` | — | Generates a short unique event ID: `evt-<12hex>`. |
| `build_raise_alert_event(incident, siem_id, target_id, target_type, rule_name, severity, raw_log)` | `alert_raised` | Builds event with actor_type `system`, outcome `detected`. Attaches severity, rule_name, raw_log to metadata. |
| `build_investigate_alert_event(incident, analyst_id, alert_id, notes)` | `alert_investigation_started` | Builds event with actor_type `blue_team`, outcome `unknown`. |
| `build_deny_alert_event(incident, analyst_id, alert_id, notes)` | `alert_denied` | Builds event with actor_type `blue_team`, outcome `false_positive`. |

---

## `core/blueactions/investigation_actions.py`

| Function | Event Type | Description |
|----------|-----------|-------------|
| `build_confirm_incident_event(incident, analyst_id, alert_id, severity, notes)` | `incident_confirmed` | Builds event with actor_type `blue_team`, outcome `detected`. **TTD anchor — this event's timestamp is used.** Severity + notes in metadata. |

---

## `core/blueactions/containment_actions.py`

| Function | Event Type | Description |
|----------|-----------|-------------|
| `build_initiate_containment_event(incident, analyst_id, target_id, target_type, strategy)` | `containment_initiated` | Builds event with outcome `None` (not yet known). Strategy in metadata. |
| `build_complete_containment_event(incident, analyst_id, target_id, target_type, event_type, outcome, notes)` | `containment_succeeded` or `containment_failed` | Builds final outcome event. `system_evaluated: True` always in metadata — system decided the outcome, not the analyst. |

---

## `core/orchestration/response_coordinator.py`

High-level coordinator for automated triage only. It must not trigger containment during measured exercises because the analyst's chosen containment action is what ATTENSE scores.

### `ContainmentPlan` (dataclass)
Fields: `analyst_id`, `target_id`, `target_type`, `strategy`, `notes`.

### `ResponseCoordinator`

| Method | Description |
|--------|-------------|
| `__init__(emitter, hive, sandbox)` | Stores injected EventEmitter, HiveClient, and TargetConnector. |
| `run_automated_response(incident_id, scenario_id, analyst_id, alert_id, plan, severity)` | Runs investigation and confirmation, then stops with `awaiting: analyst_containment_choice`. It does not initiate or complete containment automatically. |

---

## `infrastructure/eventstore/event_emitter.py`

Wraps `EventStore` + incident registry into a single interface for event persistence.

### `EventEmitter`

| Method | Description |
|--------|-------------|
| `__init__()` | Initializes empty `_incidents` dict and `_stores` defaultdict. |
| `get_or_create(incident_id, scenario_id)` | Returns existing `(Incident, EventStore)` pair, or creates new ones if first call for this ID. |
| `emit(incident, store, event)` | **Atomic persistence:** validates ownership, calls `store.add_event()` then `incident.apply_event()` to update timestamps and status. |
| `get_incident(incident_id)` | Returns existing `Incident` by ID, or `None`. |
| `get_store(incident_id)` | Returns the `EventStore` for a given incident_id. |
| `all_incidents()` | Returns a copy of all tracked incidents (for inspection endpoints). |

---

## `infrastructure/thehive/hive_client.py`

HTTP client for TheHive case management platform.

### `HiveClient`

| Method | Description |
|--------|-------------|
| `__init__(base_url, api_key, timeout)` | Configures base URL, Bearer auth header, and timeout. |
| `create_case(incident_id, title, severity)` | Creates a Hive case via `POST /api/case`. Maps severity string → Hive numeric (1–4). |
| `update_case_severity(incident_id, severity)` | Updates severity of an existing case (stubbed — logs + returns confirmation dict). |
| `add_observable(case_id, data_type, value)` | Adds an IOC observable via `POST /api/case/{id}/artifact`. |
| `_post(path, payload)` | Internal helper. Sends POST to Hive API, returns response JSON or `{}` on any failure (non-fatal). |
| `_map_severity(severity)` | Converts `low/medium/high/critical` → Hive numeric `1/2/3/4`. |

---

## `infrastructure/thehive/case_manager.py`

High-level case lifecycle management on top of `HiveClient`.

### `CaseManager`

| Method | Description |
|--------|-------------|
| `__init__(hive)` | Stores HiveClient, initializes `_case_ids` cache (incident_id → hive_case_id). |
| `open_case(incident_id, title, severity)` | Creates Hive case for a confirmed incident, caches the returned case ID. Returns case ID or None on failure. |
| `add_ioc(incident_id, data_type, value)` | Adds an IOC observable to the case for this incident. Looks up case ID from cache. Warns if no case exists. |

---

## `infrastructure/thehive/observable_manager.py`

Convenience wrapper for adding IOC observables to Hive cases.

### `ObservableManager`

| Method | Description |
|--------|-------------|
| `__init__(hive)` | Stores HiveClient instance. |
| `add_ip(case_id, ip_address)` | Adds a suspicious IP address as observable (`type: ip`). |
| `add_url(case_id, url)` | Adds a malicious URL as observable (`type: url`). |
| `add_hostname(case_id, hostname)` | Adds an affected hostname as observable (`type: hostname`). |
| `add_file_hash(case_id, file_hash)` | Adds a file hash (MD5/SHA256) as observable (`type: hash`). |

---

## `infrastructure/sandbox/target_connector.py`

Routes containment strategy commands to the sandbox target-agent via HTTP.

### `STRATEGY_ENDPOINT_MAP`
Maps strategy name → HTTP endpoint on target-agent.
Example: `"kill_process" → "/system/kill-process"`.

### `TargetConnector`

| Method | Description |
|--------|-------------|
| `__init__(base_url, timeout)` | Configures target-agent base URL and request timeout. |
| `execute_containment(target_id, strategy)` | Looks up endpoint for given strategy, sends `POST {target_id, strategy}`. Returns response dict or `{}` on failure or unknown strategy. |

---

## `infrastructure/sandbox/isolation_manager.py`

Handles full host network isolation.

### `IsolationManager`

| Method | Description |
|--------|-------------|
| `__init__(connector)` | Stores `TargetConnector`. |
| `isolate_host(target_id)` | Cuts host from network entirely. Used for: **Command Injection**, severe malware. |
| `restrict_access(target_id)` | Limits filesystem access without full isolation. Used for: **Directory Traversal**. |

---

## `infrastructure/sandbox/process_controller.py`

Controls processes on the sandbox target.

### `ProcessController`

| Method | Description |
|--------|-------------|
| `__init__(connector)` | Stores `TargetConnector`. |
| `kill_process(target_id)` | Terminates a malicious/compromised process. Used for: **Command Injection**. |
| `disable_service(target_id)` | Stops the exploited service. Used for: **Command Injection**. |

---

## `infrastructure/sandbox/firewall_manager.py`

Manages network and application-level blocking.

### `FirewallManager`

| Method | Description |
|--------|-------------|
| `__init__(connector)` | Stores `TargetConnector`. |
| `block_request(target_id)` | Blocks malicious requests at WAF/app level. Used for: **XSS**. |
| `block_path(target_id)` | Blocks access to a specific file path. Used for: **Directory Traversal**. |
| `disable_endpoint(target_id)` | Takes a vulnerable endpoint offline. Used for: **XSS**. |

---

## `schemas/requests/alert_requests.py`

Pydantic request models — enforce input shape at the API boundary.

| Class | Endpoint | Key Fields |
|-------|----------|------------|
| `RaiseAlertRequest` | `POST /raise-alert` | `siem_id`, `target_id`, `target_type`, `rule_name`, `severity`, `raw_log` |
| `InvestigateAlertRequest` | `POST /investigate-alert` | `analyst_id`, `alert_id`, `notes` |
| `DenyAlertRequest` | `POST /deny-alert` | `analyst_id`, `alert_id`, `notes` |

---

## `schemas/requests/incident_requests.py`

| Class | Endpoint | Key Fields |
|-------|----------|------------|
| `ConfirmIncidentRequest` | `POST /confirm-incident` | `analyst_id`, `alert_id`, `severity`, `notes` |

---

## `schemas/requests/containment_requests.py`

| Class | Endpoint | Key Fields |
|-------|----------|------------|
| `InitiateContainmentRequest` | `POST /initiate-containment` | `analyst_id`, `target_id`, `target_type`, `strategy` |
| `CompleteContainmentRequest` | `POST /complete-containment` | `analyst_id`, `target_id`, `target_type`, `notes` |

---

## `schemas/responses/action_response.py`

Standard envelope returned by **every** Blue Team endpoint.

### `ActionResponse` fields

| Field | Description |
|-------|-------------|
| `ok` | `True` if the action succeeded. |
| `incident_id` | Incident the action was applied to. |
| `event_id` | ID of the event that was created. |
| `event_type` | Type of the event (e.g. `alert_raised`). |
| `incident_status` | Incident status **after** this action. |
| `timestamp` | ISO-8601 timestamp of the event. |
| `message` | Human-readable result summary. |

### `ActionResponse` methods

| Method | Description |
|--------|-------------|
| `from_event(incident, event, message)` | Factory classmethod — builds a response from an `(Incident, Event)` pair. Avoids repeating field mapping in every service. |

---

## `config/settings.py`

### `Settings` (Pydantic BaseSettings — reads from env vars / `.env` file)

| Field | Default | Description |
|-------|---------|-------------|
| `service_name` | `"blueteam"` | Service identity label. |
| `environment` | `"development"` | Runtime environment (`development`, `production`). |
| `log_level` | `"INFO"` | Logging verbosity. |
| `hive_url` | `"http://localhost:9000"` | TheHive API base URL. |
| `hive_api_key` | `"changeme"` | Hive API key — override in production via env var. |
| `sandbox_url` | `"http://localhost:8020"` | Target-agent sandbox URL. |
| `event_store_type` | `"memory"` | Event store backend (`memory` \| `postgres` \| `kafka`). |

---

## `config/constants.py`

Single source of truth — **never hardcode these strings elsewhere**.

| Group | Values |
|-------|--------|
| **Incident Statuses** | `NOT_STARTED` → `ACTIVE_UNDETECTED` → `DETECTED` → `CONTAINED` → `ENDED` |
| `TERMINAL_STATUSES` | `{CONTAINED, ENDED}` — no further actions allowed after these. |
| **Event Types** | `malicious_action_executed`, `alert_raised`, `alert_investigation_started`, `alert_denied`, `incident_confirmed`, `containment_initiated`, `containment_succeeded`, `containment_failed`, `incident_ended` |
| `ALLOWED_ACTOR_TYPES` | `red_team`, `blue_team`, `system` |
| `ALLOWED_TARGET_TYPES` | `host`, `service`, `account`, `alert` |
| `ALLOWED_OUTCOMES` | `success`, `failure`, `partial`, `detected`, `blocked`, `allowed`, `unknown`, `false_positive` |
| `CONTAINMENT_STRATEGIES` | Attack type → list of valid strategies |
| `CONTAINMENT_LATE_THRESHOLD_SECONDS` | `300` (5 min) — threshold between `success` and `partial` outcome |

---

## `utils/timestamps.py`

Timing helpers for TTD and TTC calculation.

| Function | Description |
|----------|-------------|
| `utcnow()` | Returns current UTC time as a timezone-aware `datetime`. |
| `seconds_between(start, end)` | Elapsed seconds between two timestamps. Returns `None` if either is missing. |
| `calculate_ttd(incident)` | **Time to Detect** = `detection_time − start_time` in seconds. Lower = better detection. |
| `calculate_ttc(incident)` | **Time to Contain** = `containment_time − detection_time` in seconds. Lower = faster response. |
| `format_iso(dt)` | Returns ISO-8601 string for a datetime, or `None` if input is `None`. |

---

## `utils/permissions.py`

Role-based access control for analyst actions.

| Constant | Description |
|----------|-------------|
| `ROLE_PERMISSIONS` | Dict mapping role → allowed actions. Roles: `analyst`, `senior`, `system`, `admin`. |

| Function | Description |
|----------|-------------|
| `is_authorized(role, action)` | Returns `True` if the role is permitted to perform the action. |
| `require_permission(role, action)` | Asserts authorization. Raises `PermissionError` if not authorized. |

---

## Containment Strategy Reference

| Attack Type | Allowed Strategies |
|-------------|-------------------|
| Command Injection | `kill_process`, `disable_service`, `isolate_host` |
| XSS | `block_request`, `remove_payload`, `disable_endpoint` |
| Directory Traversal | `block_path`, `restrict_access` |
| Broken Auth | `lock_account`, `invalidate_session` |
