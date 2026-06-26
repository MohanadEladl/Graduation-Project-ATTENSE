# Zero-Day Agent Test Results

Date executed: 2026-06-27  
Branch: `refactor/restructure-and-pipeline-integration`  
Commit: `f81fef9`

## Automated test run

Command:

```powershell
$env:PYTHONPATH='.'; pytest tests\zeroday_agent -v --basetemp .\tmp-pytest-zeroday -p no:cacheprovider
```

Result:

```text
17 passed, 1 warning in 3.78s
```

Summary:

- Zero-day agent core function tests passed.
- MITRE ATT&CK keyword scanner tests passed.
- Report generation test passed after running pytest with an explicit writable base temp directory.

## Runtime benchmark

Command:

```powershell
$env:PYTHONPATH='apps\zeroday-agent'; py bench_zeroday.py
```

Result:

```text
[TIMER] Total elapsed: 512 ms
[RESULT] zero_day_detected: False
[RESULT] classification:    NORMAL
[RESULT] confidence:        HIGH
[RESULT] reasoning:         MITRE pre-scan found no known technique keywords in any container logs.
[RESULT] report_path:       None
```

Runtime note:

```text
No Gemini credentials — falling back to offline MITRE analysis
```

Credential configuration check:

```text
.env: no Gemini config keys
secrets\ATTENSE.env: no Gemini config keys
apps\zeroday-agent\.env: missing
zeroday-agent\.env: missing
```

Conclusion:

The zero-day automated test suite passes on the latest refactored branch. The runtime benchmark also executes successfully against the current container logs, but Gemini timing was not measured because Gemini credentials were not configured in the environment.
