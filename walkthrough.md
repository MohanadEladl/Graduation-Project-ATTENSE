# Implementation Walkthrough

We have successfully resolved the system blockers and verified the end-to-end manual alert-to-case promotion flow between Wazuh, the Blue Team service, and TheHive.

## What Was Done

### 1. Fixed Wazuh Manager & Agent Blocker
- **Root Cause**: The Wazuh manager's core analysis daemon (`wazuh-analysisd`) was failing to start up and repeatedly crashed because the `/var/ossec/logs/archives` and `/var/ossec/logs/firewall` directories did not exist inside the container.
- **Resolution**:
  1. Manually created `/var/ossec/logs/archives` and `/var/ossec/logs/firewall` directories under the manager container with the correct `wazuh:wazuh` ownership and `750` permissions.
  2. Restarted the Wazuh Manager control daemon, confirming `wazuh-analysisd` is now running stably.
  3. Resolved a duplicate enrollment warning (`Duplicate agent name: target-agent`) by removing the stale agent reference from the manager's agent list and restarting the `target-agent` container to enroll cleanly.
  4. Verified the target-agent is connected and actively reporting to the manager (marked `Active`).

### 2. Implementation of Option 3 (Manual Alert Promotion)
- **FastAPI Backend Integration**:
  - [hive_client.py](file:///d:/Graduation%20Project/restructured-sandbox/blueteam/infrastructure/thehive/hive_client.py): Added `create_alert` and patched case severity helper.
  - [hive_event_translator.py](file:///d:/Graduation%20Project/restructured-sandbox/blueteam/core/blueactions/hive_event_translator.py): Configured mapping for `("Case", "Create")` to trigger `alert_investigation_started` when an alert is promoted manually in the UI.
  - [alert_service.py](file:///d:/Graduation%20Project/restructured-sandbox/blueteam/core/services/alert_service.py): Changed the flow to create raw alerts in TheHive rather than auto-creating cases directly.

---

## Verification Results

### Automated SIEM Trigger
We simulated multiple requests to non-existent resources on `target-agent` to trigger a 404 alert:
```powershell
1..15 | ForEach-Object { try { Invoke-WebRequest -Uri "http://localhost:8081/nonexistent_$_" -UseBasicParsing -TimeoutSec 2 } catch {} }
```

### Flow Logs
1. **Wazuh Agent/Manager Connection**:
   ```log
   Wazuh agent_control. List of available agents:
      ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local
      ID: 003, Name: target-agent, IP: any, Active
   ```
2. **Signal Store Mapper**:
   ```log
   2026-05-25 15:41:09,892 INFO     signal-mapper.mapper – [mapper] rule=31101   scenario=APP-06  event_type=alert_raised  severity=high      label=broken_authentication   outcome=detected  src=172.18.0.1
   2026-05-25 15:41:11,539 INFO     httpx – HTTP Request: POST http://blueteam:8010/blueteam/raise-alert "HTTP/1.1 200 OK"
   ```
3. **Blue Team FastAPI Ingestion & TheHive Alert Creation**:
   ```log
   2026-05-25 15:41:09,885 [INFO] httpx: HTTP Request: POST http://thehive:9000/api/alert "HTTP/1.1 201 Created"
   2026-05-25 15:41:09,886 [INFO] core.services.alert_service: [AlertService] Alert created in TheHive: alert_id=~139416 for incident 'wazuh-1779723651.721361'.
   2026-05-25 15:41:12,973 [INFO] httpx: HTTP Request: POST http://thehive:9000/api/alert "HTTP/1.1 201 Created"
   2026-05-25 15:41:12,974 [INFO] core.services.alert_service: [AlertService] Alert created in TheHive: alert_id=~122904 for incident 'wazuh-1779723651.722375'.
   ```

---

## Action Items for Analyst

You can now log into TheHive UI at `http://localhost:9000` to manually promote these alerts:
1. Navigate to the **Alerts** tab.
2. Select any newly generated alert (e.g., `wazuh-1779723651.*`).
3. Review the parsed Cortex-Lite IOC artifacts.
4. Click **Import Alert** to promote it to a Case, which will automatically trigger the backend state `alert_investigation_started` via the webhook.
