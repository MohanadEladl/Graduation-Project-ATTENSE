import json
import os
import time
import sys

# Mock Alert Based on Wazuh XSS Rule 31106
MOCK_ALERT = {
    "timestamp": "2026-03-03T16:25:00.000+0000",
    "rule": {
        "id": "31106",
        "level": 7,
        "description": "Cross-site scripting (XSS) attempt",
        "groups": ["web", "attack", "xss"]
    },
    "agent": {
        "id": "001",
        "name": "sandbox-target",
        "ip": "172.18.0.2"
    },
    "location": "/var/log/nginx/access.log",
    "full_log": "172.18.0.1 - - [03/Mar/2026:16:25:00 +0000] \"GET /index.php?name=<script>alert(1)</script> HTTP/1.1\" 200 123",
    "data": {
        "srcip": "172.18.0.1"
    }
}

def test_mapper():
    print("--- Signal Mapper Functional Test ---")
    
    # Path where signal-mapper expects to find alerts (as configured in docker-compose)
    # Since we are running locally, we simulate the directory structure
    alerts_dir = "test_logs/alerts"
    alerts_file = os.path.join(alerts_dir, "alerts.json")
    os.makedirs(alerts_dir, exist_ok=True)
    
    # Clean old file
    if os.path.exists(alerts_file):
        os.remove(alerts_file)
        
    print(f"[test] Creating mock alerts file at: {alerts_file}")
    
    # In a real scenario, INCIDENT_ID must be set
    os.environ["INCIDENT_ID"] = "test-incident-001"
    
    # Add the real apps/signal-mapper directory to sys.path so `app.mapper`
    # resolves regardless of invocation cwd (this moved out of signal-mapper
    # itself into tests/integration/signal-mapper/).
    _repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    sys.path.append(os.path.join(_repo_root, "apps", "signal-mapper"))
    sys.path.append(os.path.join(_repo_root, "apps", "control-api"))
    sys.path.append(os.path.join(_repo_root, "packages", "attense-core"))
    
    try:
        from app.mapper import map_alert
        print("[test] Successfully imported map_alert")
        
        event = map_alert(MOCK_ALERT)
        
        if event is None:
            print("[FAIL] map_alert returned None")
            return
            
        print("[PASS] map_alert successfully mapped the alert.")
        print(f"[test] Event ID: {event.event_id}")
        print(f"[test] Scenario: {event.scenario_id}")
        print(f"[test] Outcome:  {event.outcome}")
        
        # Verify suitability fixes
        print("[test] Verifying suitability fixes (to_dict)...")
        event_dict = event.to_dict()
        print(f"[PASS] event.to_dict() worked. Result keys: {list(event_dict.keys())}")
        
        print("[test] Verifying JSON serialization (as used in output.py)...")
        event_json = json.dumps(event_dict)
        print(f"[PASS] json.dumps worked. Length: {len(event_json)}")
        
    except ImportError as e:
        print(f"[FAIL] Could not import app modules: {e}")
        print("Make sure you are running from the signal-mapper directory.")
    except Exception as e:
        print(f"[FAIL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_mapper()
