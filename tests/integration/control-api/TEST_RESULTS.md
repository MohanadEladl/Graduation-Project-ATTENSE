# Control API Integration Test Results

**Executed:** 2026-06-26  
**Status:** Blocked by the execution environment

```powershell
py -m unittest discover -s tests/integration/control-api -p "test_*.py" -v
```

Result: **31 tests attempted; 17 errors and 1 follow-on failure**.

The durable-store and scored-report tests create fixtures using
`tempfile.mkdtemp()`. The workspace sandbox denied writes to the system
temporary directory, preventing the repository from creating `events.jsonl` and
report-action fixture folders. The replay-deduplication failure followed the
failed durable write.

`test_webhook_local.py` is a documented manual diagnostic script and requires a
live webhook endpoint. Its connection-refused output is not an automated test
result.
