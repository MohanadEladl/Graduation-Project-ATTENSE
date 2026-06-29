# ATTENSE Test Execution Results

**Execution date:** 2026-06-26  
**Test strategy:** [TEST_STRATEGY.md](TEST_STRATEGY.md)

## Summary

| Area | Status | Result |
| --- | --- | --- |
| Unit tests | Passed | 94 tests passed |
| Blue Team API integration | Passed | 11 tests passed |
| Signal Mapper correlation integration | Passed | 7 tests passed |
| Red Team API integration | Passed | 2 tests passed |
| Zero-day agent and mapper suitability | Blocked | 17 tests passed; 1 temporary-fixture setup error |
| Control API integration | Blocked | 31 tests attempted; temporary-fixture creation is denied by the sandbox |
| Event-schema freshness | Passed | Generated schema is current |
| Docker Compose configuration | Passed | `docker compose config -q` completed successfully |
| End-to-end, Postman, Selenium, and manual frontend tests | Not executed | Require a live ATTENSE stack and/or browser automation target |

## Executed commands and results

### Unit tests — passed

```powershell
py -m unittest discover -s tests/unit -p "test_*.py" -v
```

Result: **94 tests passed**. This covers standard-event contracts, incident
state transitions, metrics, event-store behaviour, scenario validation, and
data validation.

### Blue Team API integration — passed

```powershell
py -m unittest discover -s tests/integration/blue-team-api -p "test_room_isolation.py" -v
```

Result: **11 tests passed**. Room isolation and room-header validation passed.

### Signal Mapper correlation integration — passed

```powershell
py -m unittest discover -s tests/integration/signal-mapper -p "test_signalmapper_correlation.py" -v
```

Result: **7 tests passed**. Wazuh correlation and source-event identifiers
passed.

### Red Team API integration — passed

```powershell
py -m unittest discover -s tests/integration/red-team-api -p "test_*.py" -v
```

Result: **2 tests passed**. Event payload shape and the attack start-time TTD
anchor passed.

### Zero-day agent and mapper suitability — environment blocked

```powershell
py -m pytest tests/zeroday_agent/ tests/integration/signal-mapper/test_mapper_suitability.py -v
```

Result: **17 passed, 1 setup error**. `test_generate_report` needs pytest's
`tmp_path` fixture, but the sandbox denies creation below the system temporary
directory. A rerun with `--basetemp D:\tmp\attense-pytest` was also denied.
No application assertion failed.

### Control API integration — environment blocked

```powershell
py -m unittest discover -s tests/integration/control-api -p "test_*.py" -v
```

Result: **31 attempted; 17 errors and 1 follow-on failure**. Durable-store and
scored-report fixtures use `tempfile.mkdtemp()`, and the sandbox denies writes
to the system temporary directory. The replay-deduplication failure follows
from the failed durable write, rather than a functional assertion failure.

The broad discovery command also loads `test_webhook_local.py`. It is documented
in `tests/README.md` as a manual diagnostic script that requires a live webhook
endpoint; its connection-refused output is excluded from automated results.

### Infrastructure checks — passed

```powershell
py scripts/generate_event_schema.py --check
docker compose config -q
```

Results: `standard_event.schema.json` is current, and Docker Compose
configuration validation completed successfully.

## Completion prerequisites

Run the blocked tests in an environment where Python may create temporary files.
Start the ATTENSE stack before performing Postman, manual frontend, or end-to-end
tests. Use isolated non-production data and credentials only.
