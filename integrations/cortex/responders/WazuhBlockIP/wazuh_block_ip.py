#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from wazuh_ar_client import run_wazuh_active_response  # noqa: E402

# The blocked IP is usually the attacker's address, not the agent's — try
# resolving an agent reporting from that IP first, then fall back to the
# configured agent_name (the lab's monitored host).
run_wazuh_active_response(
    observable_label="IP address",
    command="firewall-drop",
    alert_field="srcip",
    action_description="firewall-drop for IP",
)
