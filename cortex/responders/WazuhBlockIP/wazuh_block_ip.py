#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import ssl
import base64

# Default Wazuh API configuration
WAZUH_API_URL = "https://wazuh-manager:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "wazuh"

# Disable SSL verification since Wazuh usually uses a self-signed certificate
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get_token():
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    # Basic auth base64 encoded
    auth_str = f"{WAZUH_USER}:{WAZUH_PASS}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    
    req = urllib.request.Request(url, method="POST")
    req.add_header("Authorization", f"Basic {auth_b64}")
    
    try:
        response = urllib.request.urlopen(req, context=ctx)
        data = json.loads(response.read().decode('utf-8'))
        return data.get("data", {}).get("token")
    except Exception as e:
        raise Exception(f"Failed to authenticate with Wazuh API: {e}")

def trigger_active_response(token, ip_to_block):
    url = f"{WAZUH_API_URL}/active-response"
    
    # We send the firewall-drop command to agent 001
    payload = {
        "command": "firewall-drop",
        "custom": False,
        "arguments": ["-", "-", ip_to_block],
        "agents_list": ["001"]
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    
    try:
        response = urllib.request.urlopen(req, context=ctx)
        resp_data = json.loads(response.read().decode('utf-8'))
        return resp_data
    except urllib.error.HTTPError as e:
        err_data = e.read().decode('utf-8')
        raise Exception(f"HTTPError {e.code}: {err_data}")
    except Exception as e:
        raise Exception(f"Failed to trigger Wazuh active response: {e}")

def main():
    try:
        lines = sys.stdin.readlines()
        if not lines:
            print(json.dumps({"success": False, "errorMessage": "No input provided"}))
            return
        
        input_data = json.loads(lines[0])
        ip_to_block = input_data.get('data')
        
        if not ip_to_block:
            print(json.dumps({"success": False, "errorMessage": "No IP address provided in the input data"}))
            return

        # 1. Authenticate with Wazuh
        token = get_token()
        if not token:
            print(json.dumps({"success": False, "errorMessage": "Could not retrieve auth token from Wazuh"}))
            return
            
        # 2. Trigger Active Response
        ar_response = trigger_active_response(token, ip_to_block)
        
        result = {
            "success": True,
            "message": f"Successfully triggered Wazuh firewall-drop for IP: {ip_to_block}",
            "artifacts": [
                {"dataType": "info", "data": f"Wazuh Response: {json.dumps(ar_response)}"}
            ]
        }
        
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"success": False, "errorMessage": str(e)}))

if __name__ == '__main__':
    main()
