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
    extract_observable_value,
)


def main():
    try:
        input_data = read_cortex_input()
        ip_to_block = extract_observable_value(input_data)
        if not ip_to_block:
            write_cortex_output({"success": False, "errorMessage": "No IP address provided in the input data"})
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

        # The blocked IP is usually the attacker's address, not the agent's —
        # try resolving an agent reporting from that IP first, then fall back
        # to the configured agent_name (the lab's monitored host).
        agent_id = resolve_agent_id_with_fallback(wazuh_url, token, ip=ip_to_block, agent_name=agent_name)

        ar_response = trigger_active_response(
            wazuh_url, token,
            command="firewall-drop",
            alert_data={"srcip": ip_to_block},
            agent_id=agent_id,
        )

        write_cortex_output({
            "success": True,
            "full": {
                "message": f"Successfully triggered Wazuh firewall-drop for IP: {ip_to_block} (agent {agent_id})",
                "wazuhResponse": ar_response,
            },
            "operations": [],
        })
    except Exception as e:
        write_cortex_output({"success": False, "errorMessage": str(e)})


if __name__ == "__main__":
    main()
