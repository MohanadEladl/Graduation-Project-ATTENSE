# Test coverage layout

Existing tests in `tests/unit/` and `tests/integration/` remain the primary
cross-service coverage.  Focused unit suites now live beside the service or
package they exercise:

- `apps/blue-team-api/tests/` — webhook/action translation
- `apps/control-api/tests/` — local persistence helpers
- `apps/red-team-api/tests/` — learner skill persistence
- `apps/signal-mapper/tests/` — Wazuh classification
- `apps/target-lab/tests/` — containment state
- `apps/watcher/tests/` — analyst identity normalization
- `apps/zeroday-agent/tests/` — MITRE matching
- `packages/attense-core/tests/` — canonical event contract

Tests deliberately target deterministic domain behavior.  Entrypoints,
Dockerfiles, generated schemas, static assets, and external-service adapters
are covered by integration tests or configuration validation rather than
artificial one-file-per-test tests.
