#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))
from target_api_client import run_target_action  # noqa: E402

run_target_action("sanitize_input", requires_target=False)
