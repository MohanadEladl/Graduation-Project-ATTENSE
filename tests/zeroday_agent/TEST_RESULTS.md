# Zero-Day Agent Test Results

**Executed:** 2026-06-26  
**Status:** Blocked by the execution environment

```powershell
py -m pytest tests/zeroday_agent/ tests/integration/signal-mapper/test_mapper_suitability.py -v
```

Result: **17 tests passed; 1 setup error**.

`test_generate_report` requires pytest's `tmp_path` fixture. The workspace
sandbox denied creation of the required temporary directory. This is an
environment restriction; no application assertion failed. The mapper-suitability
test was included in this command and passed.
