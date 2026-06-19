#!/usr/bin/env python3
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from wazuh_ar_client import (  # noqa: E402
    read_cortex_input,
    write_cortex_output,
    get_token,
    resolve_agent_id_with_fallback,
    trigger_active_response,
)


def main():
    try:
        input_data = read_cortex_input()
        host_ip = input_data.get("data")
        if not host_ip:
            write_cortex_output({"success": False, "errorMessage": "No host IP provided in the input data"})
            return

        config = input_data.get("config", {})
        wazuh_url = config.get("wazuh_url", "https://wazuh-manager:55000").rstrip("/")
        wazuh_user = config.get("wazuh_username")
        wazuh_password = config.get("wazuh_password")
        agent_name = config.get("agent_name", "target-agent")

        if not wazuh_user or not wazuh_password:
            write_cortex_output({"success": False, "errorMessage": "Wazuh credentials are not configured for this responder"})
            return

        token = get_token(wazuh_url, wazuh_user, wazuh_password)

        # Here the IP observable IS the host to isolate, so it should match
        # the target agent's own reporting IP; fall back to agent_name if not.
        agent_id = resolve_agent_id_with_fallback(wazuh_url, token, ip=host_ip, agent_name=agent_name)

        ar_response = trigger_active_response(
            wazuh_url, token,
            command="route-null",
            alert_data={"srcip": host_ip},
            agent_id=agent_id,
        )

        write_cortex_output({
            "success": True,
            "full": {
                "message": f"Successfully triggered Wazuh route-null isolation for host: {host_ip} (agent {agent_id})",
                "wazuhResponse": ar_response,
            },
            "operations": [],
        })
    except Exception as e:
        write_cortex_output({"success": False, "errorMessage": str(e)})


if __name__ == "__main__":
    main()
