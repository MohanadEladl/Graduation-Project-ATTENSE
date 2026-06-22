import httpx

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
        response = httpx.post("http://localhost:8010/internal/webhook/hive", json=p["payload"])
        print("RESPONSE:", response.text)
    except Exception as e:
        print("ERROR:", e)
    print()
