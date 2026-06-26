# Signal Mapper Integration Test Results

**Executed:** 2026-06-26  
**Status:** Passed

```powershell
py -m unittest discover -s tests/integration/signal-mapper -p "test_signalmapper_correlation.py" -v
```

Result: **7 tests passed**.

The suite verified Wazuh alert correlation, source-event identifiers, and use of
the shared exercise incident identifier.
