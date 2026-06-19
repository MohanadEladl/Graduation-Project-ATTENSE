#!/usr/bin/env python3
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from wazuh_ar_client import (  # noqa: E402
    read_cortex_input,
    write_cortex_output,
    get_token,
    resolve_agent_id,
    trigger_active_response,
)


def main():
    try:
        input_data = read_cortex_input()
        username = input_data.get("data")
        if not username:
            write_cortex_output({"success": False, "errorMessage": "No username provided in the input data"})
            return

        config = input_data.get("config", {})
        wazuh_url = config.get("wazuh_url", "https://wazuh-manager:55000").rstrip("/")
        wazuh_user = config.get("wazuh_username")
        wazuh_password = config.get("wazuh_password")
        agent_name = config.get("agent_name", "target-agent")

        if not wazuh_user or not wazuh_password:
            write_cortex_output({"success": False, "errorMessage": "Wazuh credentials are not configured for this responder"})
            return
        if not agent_name:
            write_cortex_output({"success": False, "errorMessage": "agent_name is not configured for this responder"})
            return

        token = get_token(wazuh_url, wazuh_user, wazuh_password)

        # A username observable carries no host/IP, so the agent is resolved
        # by configured agent_name only (this lab runs a single target agent).
        agent_id = resolve_agent_id(wazuh_url, token, name=agent_name)

        # Wazuh's disable-account active-response binary reads the username
        # from the 'dstuser' field of alert.data.
        ar_response = trigger_active_response(
            wazuh_url, token,
            command="disable-account",
            alert_data={"dstuser": username},
            agent_id=agent_id,
        )

        write_cortex_output({
            "success": True,
            "full": {
                "message": f"Successfully triggered Wazuh disable-account for user: {username} (agent {agent_id})",
                "wazuhResponse": ar_response,
            },
            "operations": [],
        })
    except Exception as e:
        write_cortex_output({"success": False, "errorMessage": str(e)})


if __name__ == "__main__":
    main()
