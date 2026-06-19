"""
wazuh_ar_client.py — Shared Wazuh authentication + active-response helper.

Used by every WazuhXxx Cortex responder so the auth/lookup/trigger logic
(and its error handling) is written once instead of copy-pasted per responder.
"""
from __future__ import annotations  # Cortex's job runner uses Python 3.9 — needed for `X | None`

import sys
import os
import json
import ssl
import base64
import urllib.request
import urllib.error
import urllib.parse


def _ssl_context() -> ssl.SSLContext:
    # Wazuh's manager API typically uses a self-signed certificate in this lab.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def read_cortex_input() -> dict:
    """
    Read the JSON Cortex passes to a responder.

    Cortex's process job runner passes a job directory as argv[1] containing
    input/input.json (confirmed empirically — not documented in the local
    responder.json schema). Falls back to stdin for other invocation styles.
    """
    if len(sys.argv) > 1:
        input_path = os.path.join(sys.argv[1], "input", "input.json")
        if os.path.isfile(input_path):
            with open(input_path, "r", encoding="utf-8") as f:
                return json.load(f)

    lines = sys.stdin.readlines()
    if not lines:
        raise Exception("No input provided")
    return json.loads(lines[0])


def write_cortex_output(result: dict) -> None:
    """
    Write the responder's result for Cortex to pick up.

    Mirrors read_cortex_input's job-directory convention (argv[1]/output/).
    Cortex's "use output stream" stdout fallback does not reliably parse
    the structured `success` field (confirmed empirically — jobs were
    marked Failure even when this printed `{"success": true, ...}`), so
    writing the expected file directly is required, not just an optimization.
    """
    if len(sys.argv) > 1:
        output_dir = os.path.join(sys.argv[1], "output")
        if os.path.isdir(output_dir):
            with open(os.path.join(output_dir, "output.json"), "w", encoding="utf-8") as f:
                json.dump(result, f)
            return

    print(json.dumps(result))


def get_token(wazuh_url: str, wazuh_user: str, wazuh_password: str) -> str:
    url = f"{wazuh_url}/security/user/authenticate"
    auth_b64 = base64.b64encode(f"{wazuh_user}:{wazuh_password}".encode("utf-8")).decode("utf-8")

    req = urllib.request.Request(url, method="POST")
    req.add_header("Authorization", f"Basic {auth_b64}")

    try:
        response = urllib.request.urlopen(req, context=_ssl_context())
        data = json.loads(response.read().decode("utf-8"))
        token = data.get("data", {}).get("token")
        if not token:
            raise Exception("Wazuh authentication returned no token")
        return token
    except urllib.error.HTTPError as e:
        raise Exception(f"Failed to authenticate with Wazuh API: HTTP {e.code}: {e.read().decode('utf-8')}")
    except Exception as e:
        raise Exception(f"Failed to authenticate with Wazuh API: {e}")


def resolve_agent_id(wazuh_url: str, token: str, *, ip: str | None = None, name: str | None = None) -> str:
    """Look up a Wazuh agent ID dynamically by reporting IP or registered name."""
    if not ip and not name:
        raise Exception("resolve_agent_id requires an ip or a name")

    query = f"ip={urllib.parse.quote(ip)}" if ip else f"name={urllib.parse.quote(name)}"
    url = f"{wazuh_url}/agents?{query}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")

    try:
        response = urllib.request.urlopen(req, context=_ssl_context())
        data = json.loads(response.read().decode("utf-8"))
        items = data.get("data", {}).get("affected_items", [])
        if not items:
            raise Exception(f"No Wazuh agent found for {query}")
        return items[0]["id"]
    except urllib.error.HTTPError as e:
        raise Exception(f"Failed to look up Wazuh agent ({query}): HTTP {e.code}: {e.read().decode('utf-8')}")
    except Exception as e:
        raise Exception(f"Failed to look up Wazuh agent ({query}): {e}")


def resolve_agent_id_with_fallback(
    wazuh_url: str, token: str, *, ip: str | None = None, agent_name: str | None = None
) -> str:
    """
    Try resolving by IP first (the observable may be a known agent's
    reporting address); fall back to the configured agent_name. Raises if
    neither resolves to a real agent.
    """
    if ip:
        try:
            return resolve_agent_id(wazuh_url, token, ip=ip)
        except Exception:
            pass
    if agent_name:
        return resolve_agent_id(wazuh_url, token, name=agent_name)
    raise Exception("Could not resolve a Wazuh agent ID (no matching IP and no agent_name configured)")


def trigger_active_response(
    wazuh_url: str, token: str, *, command: str, alert_data: dict, agent_id: str
) -> dict:
    # Confirmed empirically against Wazuh 4.9.2's actual API (see
    # api/spec/spec.yaml inside the manager container — ActiveResponseBody):
    # - agents_list is a query parameter, not a body field.
    # - "custom" no longer exists; prefixing the command with "!" is the
    #   modern equivalent ("run this script directly" instead of requiring
    #   prior <command>/<active-response> registration in ossec.conf).
    # - The active-response binaries (firewall-drop, route-null,
    #   disable-account, ...) read their target value (srcip, dstuser, ...)
    #   from `alert.data`, not from a generic `arguments` array.
    url = f"{wazuh_url}/active-response?agents_list={urllib.parse.quote(agent_id)}"
    payload = {
        "command": f"!{command}",
        "alert": {"data": alert_data},
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        response = urllib.request.urlopen(req, context=_ssl_context())
        return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise Exception(f"HTTPError {e.code}: {e.read().decode('utf-8')}")
    except Exception as e:
        raise Exception(f"Failed to trigger Wazuh active response ({command}): {e}")
