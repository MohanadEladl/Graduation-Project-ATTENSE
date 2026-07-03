"""Shared client for authenticated target-agent containment responders."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from wazuh_ar_client import read_cortex_input, write_cortex_output


def run_target_action(action: str, *, requires_target: bool) -> None:
    try:
        input_data = read_cortex_input()
        target = str(input_data.get("data") or "").strip()
        if requires_target and not target:
            raise ValueError(f"{action} requires a non-empty observable")

        config = input_data.get("config", {})
        target_url = str(config.get("target_url") or "http://target-agent:80").rstrip("/")
        api_token = str(config.get("containment_api_token") or "")
        if not api_token:
            raise ValueError("Target containment API token is not configured")

        body = json.dumps({"target": target}).encode("utf-8")
        request = urllib.request.Request(
            f"{target_url}/containment/actions/{action}",
            data=body,
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Containment-Token", api_token)
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))

        if not result.get("success"):
            raise RuntimeError(result.get("error") or "Target rejected containment action")
        write_cortex_output({
            "success": True,
            "full": {
                "message": f"Applied {action} containment to {target or 'the target application'}",
                "targetResponse": result,
            },
            "operations": [],
        })
    except urllib.error.HTTPError as exc:
        error = exc.read().decode("utf-8", errors="replace")
        write_cortex_output({"success": False, "errorMessage": f"Target HTTP {exc.code}: {error}"})
    except Exception as exc:
        write_cortex_output({"success": False, "errorMessage": str(exc)})
