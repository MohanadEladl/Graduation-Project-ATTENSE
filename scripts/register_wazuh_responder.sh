#!/bin/bash
# Register a Wazuh responder in Cortex via API
# Usage: edit or export the variables below, then run: ./register_wazuh_responder.sh

set -euo pipefail

: ${CORTEX_URL:=http://localhost:9001}
: ${CORTEX_API_KEY:=REPLACE_WITH_CORTEX_API_KEY}
: ${WAZUH_API_URL:=http://wazuh-manager:55000}
: ${WAZUH_USER:=REPLACE_WAZUH_USER}
: ${WAZUH_PASS:=REPLACE_WAZUH_PASS}

# Cortex API path — adjust if your Cortex uses a different endpoint
API_PATH="/api/responder"

PAYLOAD=$(cat <<JSON
{
  "name": "wazuh-block-ip",
  "description": "Block IP via Wazuh active-response (dry-run default)",
  "type": "wazuh",
  "enabled": true,
  "config": {
    "wazuh_api_url": "${WAZUH_API_URL}",
    "wazuh_user": "${WAZUH_USER}",
    "wazuh_password": "${WAZUH_PASS}",
    "active_response": "block_ip",
    "args": ["{{case_id}}","{{data.target_ip}}","dry-run"]
  }
}
JSON
)

echo "Registering responder at ${CORTEX_URL}${API_PATH}"

curl -sS -X POST "${CORTEX_URL}${API_PATH}" \
  -H "Authorization: Bearer ${CORTEX_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" | jq .

echo "Done. Check Cortex UI or API to confirm the responder was created."
