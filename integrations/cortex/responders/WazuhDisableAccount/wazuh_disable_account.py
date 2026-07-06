#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from wazuh_ar_client import run_wazuh_active_response  # noqa: E402

# A username observable carries no host/IP, so the agent is resolved by
# configured agent_name only (this lab runs a single target agent). Wazuh's
# disable-account active-response binary reads the username from the
# 'dstuser' field of alert.data.
run_wazuh_active_response(
    observable_label="username",
    command="disable-account",
    alert_field="dstuser",
    action_description="disable-account for user",
    resolve_by_ip=False,
)
