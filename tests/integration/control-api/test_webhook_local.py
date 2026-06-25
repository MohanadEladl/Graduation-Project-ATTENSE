# Manual diagnostic script (not a unittest.TestCase) -- POSTs sample TheHive
# webhook payloads against a LOCALLY RUNNING attense-app/blueteam on :8010.
# Runs its loop at import/module-load time, so `unittest discover` over this
# directory will import it and print connection-refused errors when no stack
# is running -- that is expected and does not fail the real automated tests
# (it contributes 0 TestCase results either way). Run directly when the stack
# is up: `python test_webhook_local.py` from this directory.
import os

import httpx

# The webhook endpoint authenticates callers with TheHive's shared bearer
# secret, so this simulator must present it too. Matches attense-app's
# WEBHOOK_SECRET (defaults to the dev value).
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "changeme-webhook")
AUTH_HEADERS = {"Authorization": f"Bearer {WEBHOOK_SECRET}"}

payloads = [
    {
        "name": "alert_investigation_started",
        "payload": {
            "objectType": "Alert", "operation": "Update",
            "object": {"tags": ["attense:incident-inc-001"]},
            "details": {"owner": "john.doe"},
            "updatedBy": "john.doe"
        }
    },
    {
        "name": "alert_denied",
        "payload": {
            "objectType": "Alert", "operation": "Update",
            "object": {"status": "Ignored", "tags": ["attense:incident-inc-001"]},
            "updatedBy": "john.doe"
        }
    },
    {
        "name": "incident_confirmed",
        "payload": {
            "objectType": "Case", "operation": "Create",
            "object": {"tags": ["attense:incident-inc-001"]},
            "createdBy": "john.doe"
        }
    },
    {
        "name": "containment_initiated",
        "payload": {
            "objectType": "Task", "operation": "Update",
            "object": {"status": "InProgress", "tags": ["attense:incident-inc-001"]},
            "updatedBy": "john.doe"
        }
    },
    {
        "name": "containment_succeeded",
        "payload": {
            "objectType": "Task", "operation": "Update",
            "object": {"status": "Completed", "tags": ["attense:incident-inc-001"]},
            "updatedBy": "john.doe"
        }
    },
    {
        "name": "containment_failed",
        "payload": {
            "objectType": "TaskLog", "operation": "Create",
            "object": {"message": "Endpoint offline, CrowdStrike isolation failed", "tags": ["attense:incident-inc-001"]},
            "createdBy": "john.doe"
        }
    },
    {
        "name": "incident_ended",
        "payload": {
            "objectType": "Case", "operation": "Update",
            "object": {"status": "Closed", "resolutionStatus": "TruePositive", "tags": ["attense:incident-inc-001"]},
            "updatedBy": "john.doe"
        }
    }
]

for p in payloads:
    print(f"--- Testing: {p['name']} ---")
    try:
        response = httpx.post("http://localhost:8010/internal/webhook/hive", json=p["payload"], headers=AUTH_HEADERS)
        print("RESPONSE:", response.text)
    except Exception as e:
        print("ERROR:", e)
    print()
