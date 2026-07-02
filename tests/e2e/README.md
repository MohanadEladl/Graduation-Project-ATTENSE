# ATTENSE E2E Component Checks

This folder is the end-to-end acceptance layer for ATTENSE. Every component is
checked in two ways:

1. Manual test: you run the user-facing flow and report pass/fail feedback.
2. Automated test: Codex runs a deterministic contract check against the same
   component and verifies exact outputs where the code can be tested offline.

The full-stack flow remains:

```text
exercise start -> malicious action -> Wazuh alert -> Blue Team investigation
                                    -> containment -> final report
```

## Automated Component Gate

Run from the repo root:

```powershell
$env:PYTHONPATH = "apps/control-api;packages/attense-core"
python -m pytest -p no:cacheprovider tests/e2e/test_component_contracts.py
```

Expected result:

```text
7 passed
```

This gate is intentionally offline-friendly. It does not require Docker,
TheHive, Cortex, Wazuh, or Ollama. It validates the contracts that those live
services depend on:

- Control API scenario catalogue loads the six APP scenarios.
- Watcher command classification returns exact event types for known SOC
  commands.
- Signal Mapper maps a real Wazuh XSS alert into one ATTENSE alert event,
  correlated to the shared incident id.
- Blue Team service exposes the exact health payload.
- Blue Team TheHive webhook extraction emits the expected analyst action.
- Red Team backend exposes a valid health payload and discovers attack modules.
- Report/scoring pipeline returns a valid scored incident shape.

## Manual Component Checklist

Use this table component by component. After each manual test, send me the
component name, what you clicked or ran, and the observed result. I will compare
your result with the automated gate and then we move to the next component.

| Component | Manual test you run | Expected manual output | Automated test |
| --- | --- | --- | --- |
| Control API | Open the portal, register/login as SOC/Blue/Red users, then refresh and confirm the session stays valid. | Login succeeds, the role-specific page opens, and `/api/auth/me` reflects the logged-in role. | Scenario catalogue and auth-dependent source contracts. |
| Room lifecycle | As SOC manager, create a room. As Red Team, join it. As Blue Team, start it. | Room appears for the right company, Red Team gets room context, Blue Team gets TheHive launch context. | Room/report metadata is covered by control-api integration tests. |
| Red Team | Start a mission from the Red Team UI and open a known module such as XSS or brute force. | Mission session is created, target info loads, module steps render, and logs/timeline update. | Red Team backend health plus module discovery. |
| Target Lab | Execute the module action against the target page. | The vulnerable behavior is visible in the target, and target evidence appears for the mission. | Target contract covered by target-lab component tests. |
| Signal Mapper | Trigger an attack that Wazuh should detect. | Detection correlates to the current room incident, not a new `wazuh-*` incident. | Wazuh alert maps to `alert_raised`, `APP-01`, shared incident id, and source alert id. |
| Blue Team | From TheHive/Blue UI, investigate, confirm, preserve evidence, contain, eradicate, and validate recovery. | Each analyst action is recorded and scoped to the correct room. | Blue health and TheHive analyst-action extraction. |
| Watcher | Run SOC terminal commands such as `cat`, `sha256sum`, `iptables`, and `systemctl status` while bound to a watcher session. | Commands become the expected analyst action event types, and unknown commands are not silently dropped. | Exact command-to-event classification. |
| Final Report | End the room from the Blue/SOC flow. | Team report and per-analyst reports are generated with scores and verdicts. | Scoring/report shape and per-member scoring integration tests. |

## Live Full-Stack Smoke

When Docker is available, start the stack:

```powershell
docker compose -f docker-compose.yml -f infra/compose.dev.yml up -d
```

Then check these service probes:

```powershell
Invoke-RestMethod http://localhost:8000/health      # Red Team backend
Invoke-RestMethod http://localhost:8010/health      # Blue Team API
Invoke-RestMethod http://localhost:5050/health      # Control API
Invoke-RestMethod http://localhost:8088/health      # Signal Mapper, if exposed
```

Exact ports may differ if the compose file is changed. If a probe fails, send me
the command output and the relevant `docker compose logs <service>` excerpt.

