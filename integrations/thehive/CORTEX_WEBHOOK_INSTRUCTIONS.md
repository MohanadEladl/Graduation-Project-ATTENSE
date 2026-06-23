Cortex Webhook Responder — Quick template

Goal: fast, safe end-to-end test of TheHive → Cortex → ATTENSE containment without Wazuh.

1) Cortex responder UI settings (create a new Responder)
- Name: attense-webhook-block
- Type: Webhook (or HTTP)
- URL: http://attense-app:8010/internal/webhook/hive
- Method: POST
- Headers: Content-Type: application/json
- Body (raw JSON template):

  // containment_initiated
  {
    "objectType": "Task",
    "operation": "Update",
    "object": {
      "status": "InProgress",
      "tags": ["attense:incident-{{case_id}}"],
      "data": {"action":"block_ip","target_ip":"{{ip}}"}
    },
    "updatedBy": "cortex"
  }

  // containment_succeeded (use as second action)
  {
    "objectType": "Task",
    "operation": "Update",
    "object": {
      "status": "Completed",
      "tags": ["attense:incident-{{case_id}}"]
    },
    "updatedBy": "cortex"
  }

Notes:
- Use `{{case_id}}` and `{{ip}}` as Cortex variables when configuring how TheHive supplies responder arguments.
- Ensure the tag has prefix `attense:` so ATTENSE maps events to incidents.
- You can add an `Authorization` header if you prefer a shared secret.

2) Quick host test (bypass Cortex) — confirm ATTENSE receives payloads

Run from host (or inside any container that can reach `attense-app`):

curl command (initiate containment):

```bash
curl -X POST http://localhost:8010/internal/webhook/hive \
  -H 'Content-Type: application/json' \
  -d '{"objectType":"Task","operation":"Update","object":{"status":"InProgress","tags":["attense:incident-inc-001"],"data":{"action":"block_ip","target_ip":"10.0.0.5"}},"updatedBy":"manual-test"}'
```

curl command (succeed containment):

```bash
curl -X POST http://localhost:8010/internal/webhook/hive \
  -H 'Content-Type: application/json' \
  -d '{"objectType":"Task","operation":"Update","object":{"status":"Completed","tags":["attense:incident-inc-001"]},"updatedBy":"manual-test"}'
```

3) How to exercise the full flow quickly
- Start stack: `docker compose up -d`
- Open Cortex UI: http://localhost:9001 (login/setup if needed)
- Import/create responder using settings above
- In TheHive, open a Case / Task and run the Responder action that uses the webhook; it will POST to ATTENSE and ATTENSE will set incident status to `CONTAINING` when it receives `containment_initiated`.

4) If you want, I can generate a ready-to-import Cortex responder JSON or a Cortex API `curl` that creates the responder automatically — say the word and I'll add it.

5) Safety tips for demos
- Use dummy case IDs like `inc-001` and test IPs in a lab network.
- Keep the webhook in "dry-run" or manual-confirm mode until satisfied.

End of file.
