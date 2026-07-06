#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from wazuh_ar_client import run_wazuh_active_response  # noqa: E402

# Here the IP observable IS the host to isolate, so it should match the
# target agent's own reporting IP; fall back to agent_name if not.
run_wazuh_active_response(
    observable_label="host IP",
    command="route-null",
    alert_field="srcip",
    action_description="route-null isolation for host",
)
