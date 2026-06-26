# ATTENSE Test Strategy

## Purpose and scope

This strategy verifies that ATTENSE correctly receives security events, maps and
correlates them into incidents, persists incident data, applies containment
actions, and presents the expected user workflows. It covers the Python services
under `apps/`, the shared domain package under `packages/attense-core/`, service
integrations, and the portal and red-team frontends.

## Testing approach

### Black-box testing

Black-box tests validate externally observable behaviour without depending on
implementation details. They cover:

- API request validation, response codes, and error handling.
- Standard-event schema and producer/consumer contract compatibility.
- Event ingestion, correlation, reporting, and durable persistence.
- Room-level access isolation in the Blue Team API.
- Webhook and REST API flows, including invalid or duplicate payloads.
- End-to-end incident flows across the available services.

### White-box testing

White-box tests exercise internal logic and known edge cases. They cover:

- Event models, schema validation, and adapters.
- Incident state transitions, outcome classification, and TTD/TTC metrics.
- Repository idempotency, event ordering, and projection rebuilding.
- Signal classification and MITRE ATT&CK mapping.
- Error paths, boundary conditions, and regression cases for identified defects.

### Automated testing

Automated tests are the primary regression control. The repository uses both
Python `unittest` discovery and `pytest` suites. Tests are organized as:

- `tests/unit/` for deterministic domain and contract tests.
- `tests/integration/` for cross-module, API, persistence, correlation, and
  service-boundary tests.
- Service-local test folders for focused component coverage.
- `tests/e2e/` for end-to-end smoke tests when the complete stack is available.

Automated tests should run on every change through CI. A change is accepted only
when relevant unit and integration suites pass, generated event schemas are
current, and Docker Compose configuration validates.

### Manual testing

Manual testing complements automation where human judgement or a running
security stack is required. It includes:

- Verifying portal and red-team user journeys, navigation, rendering, and
  user-facing error states.
- Sending representative webhook and REST requests to validate real service
  integration.
- Reviewing incident timelines, containment outcomes, and generated reports.
- Browser compatibility and responsive-layout checks.

Manual exploratory testing is also used after major changes to infrastructure,
external integrations, or frontend interaction flows.

## Test environments

| Environment | Purpose | Characteristics |
| --- | --- | --- |
| Local development | Fast developer feedback | Python environment, mocked or local dependencies, deterministic test data |
| Docker Compose integration | Cross-service validation | Project services and infrastructure started from the repository Compose configuration; isolated test data and credentials |
| CI | Repeatable acceptance gates | Clean checkout that runs automated suites, schema checks, and Compose validation |
| Staging | Pre-release verification | Production-like configuration with isolated non-production data, secrets, and external service endpoints |

Production data, credentials, and destructive containment actions must never be
used in automated or exploratory tests.

## Tools

| Tool | Usage |
| --- | --- |
| Python `unittest` | Existing unit and integration-test discovery and execution |
| `pytest` | Existing pytest-based suites and fixtures, including scoring-engine tests |
| Docker and Docker Compose | Reproducible service and integration environments; Compose configuration validation |
| Postman | Manual and repeatable REST/webhook API validation using saved collections and environments |
| Browser developer tools | Manual frontend validation, network inspection, and console-error checks |
| Selenium | Planned option for repeatable browser regression tests once UI automation coverage is introduced |

## Execution and acceptance criteria

1. Run relevant unit tests for every code change.
2. Run impacted integration tests when a change crosses module, API, repository,
   or service boundaries.
3. Validate Docker Compose configuration for infrastructure changes.
4. Run end-to-end smoke tests against the Docker Compose or staging environment
   before releases.
5. Record manual test results, API collections, and discovered defects with the
   tested build or commit identifier.

Failures that affect event validity, cross-room isolation, incident correlation,
data integrity, authentication/authorization, or containment safety block a
release until resolved or formally accepted as a documented risk.
